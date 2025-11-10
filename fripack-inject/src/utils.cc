#include <string>

#if defined(_WIN32)
#include <vector>
#include <windows.h>

#elif defined(__linux__) || defined(__APPLE__) || defined(__ANDROID__)
#include <dlfcn.h>
#if defined(__linux__) || defined(__ANDROID__)
#include <link.h>
#endif
#endif

std::string get_current_module_path() {
  std::string path;

#if defined(_WIN32)
  HMODULE hModule = NULL;

  if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                        (LPCTSTR)get_current_module_path, &hModule)) {

    std::vector<char> buffer(MAX_PATH);
    DWORD length = GetModuleFileNameA(hModule, buffer.data(),
                                      static_cast<DWORD>(buffer.size()));

    while (length == buffer.size() &&
           GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
      buffer.resize(buffer.size() * 2);
      length = GetModuleFileNameA(hModule, buffer.data(),
                                  static_cast<DWORD>(buffer.size()));
    }

    if (length > 0) {
      path = std::string(buffer.data(), length);
    }
  }

#elif defined(__APPLE__)
  Dl_info info;
  if (dladdr(reinterpret_cast<void *>(get_current_module_path), &info)) {
    if (info.dli_fname) {
      path = info.dli_fname;
    }
  }

#elif defined(__linux__) && !defined(__ANDROID__)
  struct callback_data {
    std::string path;
    const void *address;
  };

  callback_data data;
  data.address = reinterpret_cast<const void *>(get_current_module_path);

  dl_iterate_phdr(
      [](struct dl_phdr_info *info, size_t size, void *void_data) -> int {
        callback_data *data = static_cast<callback_data *>(void_data);

        for (int i = 0; i < info->dlpi_phnum; i++) {
          const ElfW(Phdr) &phdr = info->dlpi_phdr[i];
          if (phdr.p_type == PT_LOAD) {
            ElfW(Addr) seg_start = info->dlpi_addr + phdr.p_vaddr;
            ElfW(Addr) seg_end = seg_start + phdr.p_memsz;

            if (data->address >= reinterpret_cast<void *>(seg_start) &&
                data->address < reinterpret_cast<void *>(seg_end)) {
              data->path = info->dlpi_name;
              return 1;
            }
          }
        }
        return 0;
      },
      &data);
  if (!data.path.empty()) {
    path = data.path;
  } else {
    Dl_info info;
    if (dladdr(reinterpret_cast<const void *>(get_current_module_path),
               &info)) {
      if (info.dli_fname) {
        path = info.dli_fname;
      }
    }
  }

#elif defined(__ANDROID__)
  Dl_info info;
  if (dladdr(reinterpret_cast<void *>(get_current_module_path), &info)) {
    if (info.dli_fname) {
      path = info.dli_fname;
    }
  }
#endif

  return path;
}
