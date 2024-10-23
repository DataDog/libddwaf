// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#pragma once

#include <yaml-cpp/yaml.h>

#include "ddwaf.h"

#include "common/base_utils.hpp"

namespace YAML {

class parsing_error : public std::exception {
public:
    explicit parsing_error(std::string what) : what_(std::move(what)) {}
    [[nodiscard]] const char *what() const noexcept override { return what_.c_str(); }

protected:
    const std::string what_;
};

template <> struct as_if<ddwaf_object, void> {
    explicit as_if(const Node &node_);
    ddwaf_object operator()() const;
    const Node &node;
};

} // namespace YAML

inline ddwaf_object yaml_to_object(const std::string &yaml)
{
    return YAML::Load(yaml).as<ddwaf_object>();
}

ddwaf_object read_file(std::string_view filename, std::string_view base = "./");
