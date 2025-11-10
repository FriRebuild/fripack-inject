#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <fstream>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "utils.h"

#ifdef __ANDROID__
#include <android/log.h>
#include <jni.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

#include "frida-gumjs.h"
#include <fmt/chrono.h>
#include <fmt/format.h>

#include "rfl.hpp"
#include "rfl/json.hpp"

#include "lzma.h"

namespace logger {

#ifdef __ANDROID__
void log(const char *tag, const std::string &message) {
  __android_log_write(ANDROID_LOG_INFO, tag, message.c_str());
}
#else
void log(const char *tag, const std::string &message) {
  auto now = std::chrono::system_clock::now();
  auto time_t = std::chrono::system_clock::to_time_t(now);
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()) %
            1000;

  std::string formatted = fmt::format("[{:%Y-%m-%d %H:%M:%S}.{:03d}] [{}] {}",
                                      now, ms.count(), tag, message);

  fmt::println("{}", formatted);

#ifdef _WIN32
  OutputDebugStringA(formatted.c_str());
  OutputDebugStringA("\n");
#endif
}
#endif

template <typename... Args>
void println(fmt::format_string<Args...> format, Args &&...args) {
  std::string message = fmt::format(format, std::forward<Args>(args)...);
  log("FriPackInject", message);
}
} // namespace logger

class GumJSHookManager {
private:
  std::unique_ptr<std::thread> hook_thread_;

  GumScriptBackend *backend_ = nullptr;
  GCancellable *cancellable_ = nullptr;
  GError *error_ = nullptr;
  GumScript *script_ = nullptr;
  GMainContext *context_ = nullptr;
  GMainLoop *loop_ = nullptr;
  bool initialized_ = false;

public:
  GumJSHookManager() = default;
  ~GumJSHookManager() { cleanup(); }

  GumJSHookManager(const GumJSHookManager &) = delete;
  GumJSHookManager &operator=(const GumJSHookManager &) = delete;

  std::vector<char> read_file(const std::string &filepath) {
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
      logger::println("File open failed: {}", filepath);
      return {};
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<char> buffer(size);
    if (!file.read(buffer.data(), size)) {
      logger::println("File read failed: {}", filepath);
      return {};
    }

    return buffer;
  }

  static void on_message(const gchar *message, GBytes *data,
                         gpointer user_data) {
    JsonParser *parser = json_parser_new();
    if (!json_parser_load_from_data(parser, message, -1, nullptr)) {
      logger::println("Failed to parse JSON message");
      g_object_unref(parser);
      return;
    }

    JsonNode *root_node = json_parser_get_root(parser);
    if (!root_node) {
      g_object_unref(parser);
      return;
    }

    JsonObject *root = json_node_get_object(root_node);
    if (!root) {
      g_object_unref(parser);
      return;
    }

    const gchar *type = json_object_get_string_member(root, "type");
    if (type && strcmp(type, "log") == 0) {
      const gchar *log_message = json_object_get_string_member(root, "payload");
      if (log_message) {
        logger::println("[*] log: {}", log_message);
      }
    } else {
      logger::println("[*] {}", message);
    }

    g_object_unref(parser);
  }

  std::promise<void> start_js_thread(const std::string &js_content) {
    logger::println("[*] Starting GumJS hook thread");

    std::promise<void> init_promise;
    std::future<void> init_future = init_promise.get_future();
    std::thread([this, js_content = std::move(js_content),
                 promise = std::move(init_promise)]() mutable {
      gum_init_embedded();
      backend_ = gum_script_backend_obtain_qjs();
      script_ =
          gum_script_backend_create_sync(backend_, "example", js_content.data(),
                                         nullptr, cancellable_, &error_);
      if (error_) {
        throw std::runtime_error(
            fmt::format("Failed to create script: {}", error_->message));
      }

      gum_script_set_message_handler(script_, on_message, nullptr, nullptr);
      gum_script_load_sync(script_, cancellable_);

      context_ = g_main_context_get_thread_default();
      while (g_main_context_pending(context_)) {
        g_main_context_iteration(context_, FALSE);
      }

      promise.set_value();
      loop_ = g_main_loop_new(g_main_context_get_thread_default(), FALSE);
      g_main_loop_run(loop_);
    }).detach();
    // init_future.get();
    return init_promise;
  }

  void stop() {
    if (loop_) {
      g_main_loop_quit(loop_);
    }

    if (hook_thread_ && hook_thread_->joinable()) {
      hook_thread_->join();
    }
  }

private:
  void cleanup() {
    stop();

    if (script_) {
      g_object_unref(script_);
      script_ = nullptr;
    }

    if (cancellable_) {
      g_object_unref(cancellable_);
      cancellable_ = nullptr;
    }

    if (loop_) {
      g_main_loop_unref(loop_);
      loop_ = nullptr;
    }

    if (error_) {
      g_error_free(error_);
      error_ = nullptr;
    }
  }
};

static std::unique_ptr<GumJSHookManager> gumjs_hook_manager;

#pragma pack(push, 1)
struct EmbeddedConfig {
  int32_t magic1 = 0x0d000721;
  int32_t magic2 = 0x1f8a4e2b;
  int32_t version = 1;

  int32_t data_size = 0;
  int32_t data_offset = 0; // Offset from the start of file.
  bool data_xz = false;    // Whether the data is compressed with xz.
};
#pragma pack(pop)

struct EmbeddedConfigData {
  enum class Mode : int32_t {
    EmbedJs = 1,
  } mode;
  std::optional<std::string> js_filepath;
  std::optional<std::string> js_content;
};

static EmbeddedConfig g_embedded_config{};

void _main() {
  logger::println("[*] Library loaded, starting GumJS hook");

  if (g_embedded_config.magic1 != 0x0d000721 ||
      g_embedded_config.magic2 != 0x1f8a4e2b ||
      g_embedded_config.version != 1) {
    logger::println("Invalid embedded config");
    return;
  }

#pragma optimize("", off)
  auto mod = get_current_module_path();
  std::ifstream file(mod, std::ios::binary);
  if (!file.is_open()) {
    logger::println("Failed to open module file: {}", mod);
    return;
  }
  file.seekg(g_embedded_config.data_offset, std::ios::beg);
  std::vector<char> data(g_embedded_config.data_size);
  file.read(data.data(), g_embedded_config.data_size);
  auto json_str = std::string(data.data(), g_embedded_config.data_size);
  logger::println("Embedded config offset: {}, size: {}, JSON: {}",
                  g_embedded_config.data_offset, g_embedded_config.data_size,
                  json_str);
#pragma optimize("", on)
  if (auto res = rfl::json::read<EmbeddedConfigData>(json_str)) {
    gumjs_hook_manager = std::make_unique<GumJSHookManager>();

    auto config = res.value();
    std::string js_content;
    if (config.mode == EmbeddedConfigData::Mode::EmbedJs) {
      if (config.js_content) {
        js_content = *config.js_content;
        gumjs_hook_manager->start_js_thread(js_content);
      } else {
        logger::println("No JS content or filepath provided");
        return;
      }
    } else {
      logger::println("Unsupported embedded config mode: {}",
                      static_cast<int32_t>(config.mode));
      return;
    }
  } else {
    logger::println("Failed to parse embedded config data: {}",
                    res.error().what());
    return;
  }
}

#ifdef _WIN32
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
  switch (fdwReason) {
  case DLL_PROCESS_ATTACH:
    _main();
    break;
  case DLL_PROCESS_DETACH:
    if (gumjs_hook_manager) {
      gumjs_hook_manager->stop();
      gumjs_hook_manager.reset();
    }
    break;
  }
  return TRUE;
}
#else
__attribute__((constructor)) static void _library_main() { _main(); }
#endif