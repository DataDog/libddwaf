// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <type_traits>

namespace ddwaf {

// https://stackoverflow.com/questions/43992510/enable-if-to-check-if-value-type-of-iterator-is-a-pair
template <typename> struct is_pair : std::false_type {};
template <typename T, typename U> struct is_pair<std::pair<T, U>> : std::true_type {};

} // namespace ddwaf
