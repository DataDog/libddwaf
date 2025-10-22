// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <exception>

namespace ddwaf {

class timeout_exception : public std::exception {};
class incomplete_ruleset : public std::exception {};

} // namespace ddwaf
