#pragma once
#include <optional>
#include <string>
#include <cstdint>

namespace fripack::config {
struct EmbeddedConfigData {
  enum class Mode : int32_t {
    EmbedJs = 1,
    WatchPath = 2,
  } mode;
  std::optional<std::string> js_filepath;
  std::optional<std::string> js_content;
  std::optional<std::string> watch_path;
};

const EmbeddedConfigData &configData();
} // namespace fripack::config