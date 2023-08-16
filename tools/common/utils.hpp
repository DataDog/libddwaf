// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iostream>
#include <limits>
#include <string_view>
#include <utility>
#include <yaml-cpp/yaml.h>

#include "ddwaf.h"
#include "log.hpp"


namespace YAML
{

class parsing_error : public std::exception
{
public:
    explicit parsing_error(std::string what) : what_(std::move(what)) {}
    [[nodiscard]] const char *what() const noexcept override { return what_.c_str(); }

protected:
    const std::string what_;
};

template <>
struct as_if<ddwaf_object, void>
{
    explicit as_if(const Node& node_) : node(node_) {}
    ddwaf_object operator()() const;
    const Node& node;
};

} // namespace YAML

ddwaf_object json_to_object(const std::string &json);

YAML::Node object_to_yaml(const ddwaf_object &obj);
std::string object_to_json(const ddwaf_object &obj);

const char* level_to_str(DDWAF_LOG_LEVEL level);

void log_cb(DDWAF_LOG_LEVEL level, const char* function, const char* file,
    unsigned line, const char* message, uint64_t  length);

std::string read_file(std::string_view filename);
