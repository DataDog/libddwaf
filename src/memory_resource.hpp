// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2023 Datadog, Inc.

#pragma once

#include <version>

#if defined(__cpp_lib_memory_resource)
#  include <memory_resource>
#else
#  include <experimental/memory_resource>
#  include <string>
#  include <unordered_map>
#  include <unordered_set>
#  include <vector>

namespace std { // NOLINT(cert-dcl58-cpp)
namespace experimental::pmr {
template <class Key, class T, class Hash = std::hash<Key>, class KeyEqual = std::equal_to<Key>>
using unordered_map =
    std::unordered_map<Key, T, Hash, KeyEqual, polymorphic_allocator<std::pair<const Key, T>>>;

template <class Key, class Hash = std::hash<Key>, class Pred = std::equal_to<Key>>
using unordered_set = std::unordered_set<Key, Hash, Pred, polymorphic_allocator<Key>>;

template <class T> using vector = std::vector<T, polymorphic_allocator<T>>;

using string = std::basic_string<char, std::char_traits<char>, polymorphic_allocator<char>>;

} // namespace experimental::pmr

namespace pmr = std::experimental::pmr;
} // namespace std

#  if !defined(__cpp_lib_experimental_memory_resources)
#    include <libcxx-compat/monotonic_buffer_resource.hpp>
#  endif

#endif
