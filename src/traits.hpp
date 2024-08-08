// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <tuple>
#include <type_traits>
#include <utility>

// Generate a tuple containing a subset of the arguments
// Reference: https://stackoverflow.com/questions/71301988

template <typename... Ts> struct typelist;

template <std::size_t N, typename, typename> struct make_n_typelist;

template <typename Keep, typename Drop> struct make_n_typelist<0, Keep, Drop> {
    using type = Keep;
};

template <std::size_t N, typename K, typename... Ks, typename... Ds>
    requires(N > 0)
struct make_n_typelist<N, typelist<Ks...>, typelist<K, Ds...>> {
    using type = typename make_n_typelist<N - 1, typelist<Ks..., K>, typelist<Ds...>>::type;
};

template <std::size_t N, typename... Ts>
using make_n_typelist_t = typename make_n_typelist<N, typelist<>, typelist<Ts...>>::type;

template <typename... Ts> struct tuple_from_typelist;

template <typename... Ts> struct tuple_from_typelist<typelist<Ts...>> {
    using type = std::tuple<std::remove_cv_t<std::remove_reference_t<Ts>>...>;
};

template <std::size_t N, typename... Args>
using n_tuple_from_args_t = typename tuple_from_typelist<make_n_typelist_t<N, Args...>>::type;

// Function traits
template <std::size_t N, typename Class, typename... Args> struct function_traits {
    using tuple_type = n_tuple_from_args_t<N, Args...>;
    static inline constexpr std::size_t nargs = std::tuple_size_v<tuple_type>;
    template <std::size_t I> using arg_type = std::tuple_element_t<I, tuple_type>;
};

template <std::size_t N, typename Result, typename Class, typename... Args>
function_traits<N, Class, Args...> make_traits(Result (Class::*)(Args...) const);

template <std::size_t N, typename Result, typename Class, typename... Args>
function_traits<N, Class, Args...> make_traits(Result (Class::*)(Args...));

// https://stackoverflow.com/questions/43992510/enable-if-to-check-if-value-type-of-iterator-is-a-pair
template <typename> struct is_pair : std::false_type {};
template <typename T, typename U> struct is_pair<std::pair<T, U>> : std::true_type {};

template <typename T>
concept is_pair_v = is_pair<T>::value;
