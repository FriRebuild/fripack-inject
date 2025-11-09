#include <string>
#include <string_view>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <fstream>
#include <iostream>

#ifdef __ANDROID__
#include <android/log.h>
#include <jni.h>
#endif

#ifdef _WIN32
#include <windows.h>
#include <debugapi.h>
#endif

#include "frida-gumjs.h"

class GumJSHookManager {
private:
    std::mutex mtx_;
    std::condition_variable cond_;
    bool script_loaded_ = false;
    
    GumScriptBackend* backend_ = nullptr;
    GCancellable* cancellable_ = nullptr;
    GError* error_ = nullptr;
    GumScript* script_ = nullptr;
    GMainContext* context_ = nullptr;
    GMainLoop* loop_ = nullptr;
    std::thread gum_thread_;

public:
    GumJSHookManager() = default;
    ~GumJSHookManager() {
        cleanup();
    }

    // 删除拷贝构造和赋值
    GumJSHookManager(const GumJSHookManager&) = delete;
    GumJSHookManager& operator=(const GumJSHookManager&) = delete;

    int hook(const std::string& script_path);
    void cleanup();

private:
    int hook_func(const std::string& script_path);
    static void on_message(const gchar* message, GBytes* data, gpointer user_data);
    static std::string read_file(const std::string& file_path);
};

// 跨平台日志函数
template<typename... Args>
void gumjs_log(std::string_view tag, std::format_string<Args...> fmt, Args&&... args) {
    std::string message = std::format(fmt, std::forward<Args>(args)...);
    std::string formatted_message = std::format("[{}] {}", tag, message);
    
#ifdef __ANDROID__
    __android_log_print(ANDROID_LOG_DEBUG, tag.data(), "%s", message.c_str());
#else
    // 获取当前时间
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto tm = *std::localtime(&time_t);
    
    // 格式化时间字符串
    char time_buf[64];
    std::strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm);
    
    // 输出到stdout
    std::cout << "[" << time_buf << "] " << formatted_message << std::endl;
    
#ifdef _WIN32
    // Windows下同时输出到调试器
    OutputDebugStringA(formatted_message.c_str());
    OutputDebugStringA("\n");
#endif
#endif
}

// 简化版本的日志函数（类似std::println签名）
template<typename... Args>
void gumjs_println(std::format_string<Args...> fmt, Args&&... args) {
    gumjs_log("FGum", fmt, std::forward<Args>(args)...);
}

std::string GumJSHookManager::read_file(const std::string& file_path) {
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        gumjs_println("File open failed: {}", file_path);
        return "";
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::string content(size, '\0');
    if (!file.read(content.data(), size)) {
        gumjs_println("File read failed: {}", file_path);
        return "";
    }

    return content;
}

void GumJSHookManager::on_message(const gchar* message, GBytes* data, gpointer user_data) {
    JsonParser* parser;
    JsonObject* root;
    const gchar* type;

    parser = json_parser_new();
    json_parser_load_from_data(parser, message, -1, nullptr);
    root = json_node_get_object(json_parser_get_root(parser));

    type = json_object_get_string_member(root, "type");
    if (strcmp(type, "log") == 0) {
        const gchar* log_message = json_object_get_string_member(root, "payload");
        gumjs_println("Log: {}", log_message);
    } else {
        gumjs_println("Message: {}", message);
    }

    g_object_unref(parser);
}

int GumJSHookManager::hook_func(const std::string& script_path) {
    gumjs_println("Starting GumJS hook...");
    
    gum_init_embedded();
    backend_ = gum_script_backend_obtain_qjs();
    
    std::string js_code = read_file(script_path);
    if (js_code.empty()) {
        return 1;
    }

    script_ = gum_script_backend_create_sync(backend_, "example", js_code.c_str(), 
                                            nullptr, cancellable_, &error_);
    
    if (error_ != nullptr) {
        gumjs_println("Script creation failed: {}", error_->message);
        return 1;
    }

    gum_script_set_message_handler(script_, on_message, nullptr, nullptr);
    gum_script_load_sync(script_, cancellable_);

    // 处理已有的事件
    context_ = g_main_context_get_thread_default();
    while (g_main_context_pending(context_)) {
        g_main_context_iteration(context_, FALSE);
    }

    // 通知主线程脚本已加载完成
    {
        std::lock_guard<std::mutex> lock(mtx_);
        script_loaded_ = true;
        cond_.notify_one();
    }

    gumjs_println("Script loaded successfully, starting event loop...");
    loop_ = g_main_loop_new(g_main_context_get_thread_default(), FALSE);
    g_main_loop_run(loop_); // 阻塞在这里

    return 0;
}

int GumJSHookManager::hook(const std::string& script_path) {
    gumjs_println("Initializing GumJS hook for: {}", script_path);
    
    // 在单独的线程中运行GumJS
    gum_thread_ = std::thread([this, script_path]() {
        this->hook_func(script_path);
    });

    // 等待脚本加载完成或超时
    {
        std::unique_lock<std::mutex> lock(mtx_);
        auto timeout = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        
        if (cond_.wait_until(lock, timeout, [this]() { return script_loaded_; })) {
            gumjs_println("GumJS hook initialized successfully");
        } else {
            gumjs_println("GumJS hook initialization timeout");
            return 1;
        }
    }

    return 0;
}

void GumJSHookManager::cleanup() {
    gumjs_println("Cleaning up GumJS hook...");
    
    if (loop_) {
        g_main_loop_quit(loop_);
    }
    
    if (gum_thread_.joinable()) {
        gum_thread_.join();
    }
    
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
    
    gumjs_println("GumJS hook cleanup completed");
}