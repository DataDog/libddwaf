// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <platform.hpp>

namespace ddwaf {

#if defined(_WIN32) || defined(WIN32) || defined(__WIN32__) || defined(__NT__)
platform system_platform::platform_override = platform::windows;
#elif defined(linux) || defined(__linux__) || defined(__unix__)
platform system_platform::platform_override = platform::linux;
#elif defined(__APPLE__)
platform system_platform::platform_override = platform::macos;
#else
platform system_platform::platform_override = platform::unknown;
#endif
} // namespace ddwaf
