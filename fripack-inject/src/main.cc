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
#include <filesystem>
#include <atomic>

#include "logger.h"

#ifdef __ANDROID__
#include <android/log.h>
#include <jni.h>
#elif defined(_WIN32)
#include <windows.h>
#include <fileapi.h>
#endif

#include "frida-gumjs.h"

#include "hooks.h"
#include "stacktrace.h"
#include "config.h"

namespace fripack {

class GumJSHookManager {
private:
  std::unique_ptr<std::thread> hook_thread_;
  std::unique_ptr<std::thread> watch_thread_;

  GumScriptBackend *backend_ = nullptr;
  GCancellable *cancellable_ = nullptr;
  GError *error_ = nullptr;
  GumScript *script_ = nullptr;
  GMainContext *context_ = nullptr;
  GMainLoop *loop_ = nullptr;
  bool initialized_ = false;
  std::atomic<bool> should_stop_watching_{false};
  std::string watch_path_;
  std::filesystem::file_time_type last_write_time_;

public:
  GumJSHookManager() = default;
  ~GumJSHookManager() { cleanup(); }

  GumJSHookManager(const GumJSHookManager &) = delete;
  GumJSHookManager &operator=(const GumJSHookManager &) = delete;

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
      logger::println("[*] Obtained Gum Script Backend");

      fripack::hooks::init();

      script_ =
          gum_script_backend_create_sync(backend_, "script", js_content.data(),
                                         nullptr, cancellable_, &error_);
      logger::println("[*] Created Gum Script");

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

  std::string read_file_content(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
      logger::println("Failed to open file: {}", filepath);
      return "";
    }
    
    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    return content;
  }

  void reload_script(const std::string& new_content) {
    if (!script_) {
      logger::println("No script to reload");
      return;
    }

    logger::println("[*] Reloading script with new content");
    
    // Unload the old script
    gum_script_unload_sync(script_, cancellable_);
    
    // Create new script with updated content
    GumScript *new_script = gum_script_backend_create_sync(
        backend_, "script", new_content.data(), nullptr, cancellable_, &error_);
    
    if (error_) {
      logger::println("Failed to create new script: {}", error_->message);
      g_error_free(error_);
      error_ = nullptr;
      return;
    }

    // Clean up old script
    g_object_unref(script_);
    
    // Set up new script
    script_ = new_script;
    gum_script_set_message_handler(script_, on_message, nullptr, nullptr);
    gum_script_load_sync(script_, cancellable_);
    
    logger::println("[*] Script reloaded successfully");
  }

  void start_file_watcher(const std::string& watch_path) {
    watch_path_ = watch_path;
    should_stop_watching_ = false;
    
    // Get initial file write time
    try {
      last_write_time_ = std::filesystem::last_write_time(watch_path_);
    } catch (const std::exception& e) {
      logger::println("Failed to get initial file time: {}", e.what());
      return;
    }

    watch_thread_ = std::make_unique<std::thread>([this]() {
      logger::println("[*] Started watching file: {}", watch_path_);
      
      while (!should_stop_watching_) {
        try {
          auto current_write_time = std::filesystem::last_write_time(watch_path_);
          
          if (current_write_time != last_write_time_) {
            logger::println("[*] File change detected, reloading...");
            last_write_time_ = current_write_time;
            
            std::string new_content = read_file_content(watch_path_);
            if (!new_content.empty()) {
              reload_script(new_content);
            }
          }
        } catch (const std::exception& e) {
          logger::println("Error watching file: {}", e.what());
        }
        
        // Check every 500ms
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
      }
      
      logger::println("[*] File watcher stopped");
    });
  }

  void stop() {
    should_stop_watching_ = true;
    
    if (watch_thread_ && watch_thread_->joinable()) {
      watch_thread_->join();
    }
    
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

void _fi_main() {
  logger::println("[*] Library loaded, starting GumJS hook");

  // logger::println("Embedded config offset: {}, size: {}, JSON: {}",
  //                 g_embedded_config.data_offset, g_embedded_config.data_size,
  //                 json_str);
  try {
    std::thread([=]() {
      GumJSHookManager *gumjs_hook_manager;
      auto config = fripack::config::configData();

      gumjs_hook_manager = new GumJSHookManager();
      std::string js_content;
      
      if (config.mode == config::EmbeddedConfigData::Mode::EmbedJs) {
        if (config.js_content) {
          js_content = *config.js_content;
          gumjs_hook_manager->start_js_thread(js_content);
        } else {
          logger::println("No JS content provided for EmbedJs mode");
          return;
        }
      } else if (config.mode == config::EmbeddedConfigData::Mode::WatchPath) {
        if (config.watch_path) {
          js_content = gumjs_hook_manager->read_file_content(*config.watch_path);
          if (js_content.empty()) {
            logger::println("Failed to read initial JS content from: {}", *config.watch_path);
            return;
          }
          
          auto init_promise = gumjs_hook_manager->start_js_thread(js_content);

          gumjs_hook_manager->start_file_watcher(*config.watch_path);
        } else {
          logger::println("No watch path provided for WatchPath mode");
          return;
        }
      } else {
        logger::println("Unsupported embedded config mode: {}",
                        static_cast<int32_t>(config.mode));
        return;
      }
    }).detach();
  } catch (const std::exception &e) {
    logger::println("Exception while parsing embedded config data: {}",
                    e.what());
    return;
  }
}
} // namespace fripack

#ifdef _WIN32
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
  switch (fdwReason) {
  case DLL_PROCESS_ATTACH:
    fripack::_fi_main();
    break;
  case DLL_PROCESS_DETACH:
    break;
  }
  return TRUE;
}
#else
__attribute__((constructor)) static void _library_main() {
  fripack::_fi_main();
}
#endif