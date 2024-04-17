// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <re2/re2.h>
#include <string_view>

namespace ddwaf {

std::unique_ptr<re2::RE2> regex_init(std::string_view pattern, bool case_sensitive = false);
bool regex_match(
    re2::RE2 &regex, std::string_view subject, re2::RE2::Anchor anchor = re2::RE2::UNANCHORED);

} // namespace ddwaf
