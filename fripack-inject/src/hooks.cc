#include "hooks.h"
#include "logger.h"

#include <frida-gumjs.h>

#if defined(__ANDROID__) && (defined(__aarch64__) || defined(__arm__))
#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <shadowhook.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace fripack::hooks {
void init() {

  if (auto errn = shadowhook_init(SHADOWHOOK_MODE_SHARED, false)) {
    logger::println("Shadowhook init failed: {}", shadowhook_to_errmsg(errn));
    return;
  }

  static void *orig_g_mapped_file_new;
  shadowhook_hook_func_addr(
      reinterpret_cast<void *>(&g_mapped_file_new),
      reinterpret_cast<void *>(+[](const gchar *filename, gboolean writable,
                                   GError **error) -> GMappedFile * {
        std::string fname = filename ? filename : "(null)";
        if (fname.starts_with("/apex/com.android.runtime/bin/linker")) {
          logger::println("[Shadowhook] g_mapped_file_new called:\n");
          logger::println("  filename: {}", filename ? filename : "(null)");
          logger::println("  writable: {}", writable ? "true" : "false");

          typedef struct {
            gchar *content;
            gsize length;
            gboolean writable;
            gint ref_count;
            gboolean is_custom_buffer;
          } CustomMappedFile;
          
          logger::println("  [INTERCEPT] Replacing mmap with traditional read");

          int fd = open(filename, writable ? O_RDWR : O_RDONLY);
          if (fd == -1) {
            logger::println("  [ERROR] Failed to open file: {}",
                            filename ? filename : "(null)");
            if (error) {
              *error =
                  g_error_new(G_FILE_ERROR, g_file_error_from_errno(errno),
                              "Failed to open file: %s", g_strerror(errno));
            }
            return nullptr;
          }

          struct stat st;
          if (fstat(fd, &st) == -1) {
            logger::println("  [ERROR] Failed to stat file");
            close(fd);
            return nullptr;
          }

          gsize file_size = st.st_size;
          logger::println("  file_size: {}", file_size);

          gchar *buffer = static_cast<gchar *>(g_malloc(file_size));
          if (!buffer) {
            logger::println("  [ERROR] Failed to allocate buffer");
            close(fd);
            return nullptr;
          }

          ssize_t bytes_read = read(fd, buffer, file_size);
          close(fd);

          if (bytes_read != static_cast<ssize_t>(file_size)) {
            printf("  [ERROR] Failed to read complete file\n");
            g_free(buffer);
            return nullptr;
          }

          CustomMappedFile *custom_file = g_new0(CustomMappedFile, 1);
          custom_file->content = buffer;
          custom_file->length = file_size;
          custom_file->writable = writable;
          custom_file->ref_count = 1;
          custom_file->is_custom_buffer = true;

          logger::println("  [SUCCESS] Created custom buffer: {}, size: {}",
                          custom_file->content, custom_file->length);

          return reinterpret_cast<GMappedFile *>(custom_file);
        } else {
          return (decltype (&g_mapped_file_new)(orig_g_mapped_file_new))(
              filename, writable, error);
        }
      }),
      &orig_g_mapped_file_new);
}

} // namespace fripack::hooks
#else
namespace fripack::hooks {
void init() {}
} // namespace fripack::hooks
#endif