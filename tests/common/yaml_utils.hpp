// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#pragma once

#include <fstream>
#include <yaml-cpp/yaml.h>

#include "ddwaf.h"

#include "common/base_utils.hpp"

namespace YAML {

class parsing_error : public std::exception {
public:
    explicit parsing_error(std::string what) : what_(std::move(what)) {}
    [[nodiscard]] const char *what() const noexcept override { return what_.c_str(); }

protected:
    std::string what_;
};

template <> struct as_if<ddwaf_object, void> {
    explicit as_if(const Node &node_);
    ddwaf_object operator()() const;
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    const Node &node;
};

template <> struct as_if<ddwaf::owned_object, void> {
    explicit as_if(const Node &node_);
    ddwaf::owned_object operator()() const;
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    const Node &node;
};

} // namespace YAML

template <typename T> inline T yaml_to_object(const std::string &yaml)
{
    return YAML::Load(yaml).as<T>();
}

template <typename T>
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
T read_file(std::string_view filename, std::string_view base = "./")
{
    std::string base_dir{base};
    if (*base_dir.end() != '/') {
        base_dir += '/';
    }

    auto file_path = base_dir + "yaml/" + std::string{filename};

    DDWAF_DEBUG("Opening {}", file_path.c_str());

    std::ifstream file(file_path.c_str(), std::ios::in);
    if (!file) {
        throw std::system_error(errno, std::generic_category());
    }

    // Create a buffer equal to the file size
    std::string buffer;
    file.ignore(std::numeric_limits<std::streamsize>::max());
    std::streamsize length = file.gcount();
    file.clear();
    buffer.resize(length, '\0');
    file.seekg(0, std::ios::beg);

    file.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    file.close();

    return yaml_to_object<T>(buffer);
}
