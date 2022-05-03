// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.
#pragma once

#include <ddwaf.h>
#include <yaml-cpp/yaml.h>

namespace YAML
{

class parsing_error : public std::exception
{
public:
    parsing_error(const std::string& what) : what_(what) {}
    const char* what() { return what_.c_str(); }

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

}


