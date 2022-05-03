// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

#include <iostream>
#include <fstream>

#include <ddwaf.h>
#include <yaml-cpp/yaml.h>

#include "rule_parser.hpp"
#include "utils.hpp"
#include "yaml_helpers.hpp"

namespace ddwaf::benchmark::rule_parser
{

ddwaf_object from_file(fs::path &filename)
{
    std::string rule_str = utils::read_file(filename);
    YAML::Node doc       = YAML::Load(rule_str);
    return doc.as<ddwaf_object>();
}

}
