// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include <optional>
#include <unordered_map>

#include "utils.hpp"

namespace ddwaf {

template <typename T, typename Nested = void> class base_cache_entry;

template <typename T, typename Nested = void> class cache_entry;

template <typename T, typename Nested = void> class cache_entry_ref;

template <typename> struct is_cache_entry : std::false_type {};

template <typename T, typename Nested>
struct is_cache_entry<cache_entry<T, Nested>> : std::true_type {};

template <typename T> inline constexpr bool is_cache_entry_v = is_cache_entry<T>::value;

template <typename T>
concept CacheEntry = is_cache_entry_v<std::remove_cvref_t<T>>;

template <typename Key, CacheEntry T> class cache_store;
template <CacheEntry T> class sequential_cache_store;

template <typename> struct is_cache_store : std::false_type {};

template <typename Key, CacheEntry T>
struct is_cache_store<cache_store<Key, T>> : std::true_type {};

template <CacheEntry T> struct is_cache_store<sequential_cache_store<T>> : std::true_type {};

template <typename T> inline constexpr bool is_cache_store_v = is_cache_store<T>::value;

template <typename T>
concept CacheStore = is_cache_store_v<std::remove_cvref_t<T>>;

template <typename T>
concept CacheOfAnyType =
    is_cache_store_v<std::remove_cvref_t<T>> || is_cache_entry_v<std::remove_cvref_t<T>>;

// Base cache entry
template <typename T, typename Nested>
    requires(!CacheOfAnyType<T>) && CacheOfAnyType<Nested>
class base_cache_entry<T, Nested> {
public:
    using base_type = base_cache_entry<T, Nested>;

    using value_type = T;
    using nested_value_type = typename Nested::base_type;

    base_cache_entry() = default;
    base_cache_entry(const base_cache_entry &) = default;
    base_cache_entry &operator=(const base_cache_entry &) = default;
    base_cache_entry(base_cache_entry &&) = default;
    base_cache_entry &operator=(base_cache_entry &&) = default;
    virtual ~base_cache_entry() = default;

    virtual const value_type *operator->() const = 0;
    virtual value_type *operator->() = 0;

    virtual const value_type &first() const = 0;
    virtual value_type &first() = 0;
    virtual const nested_value_type &second() const = 0;
    virtual nested_value_type &second() = 0;
};

template <typename T, typename Nested>
    requires CacheOfAnyType<T> && CacheOfAnyType<Nested>
class base_cache_entry<T, Nested> {
public:
    using base_type = base_cache_entry<T, Nested>;

    using value_type = T::base_type;
    using nested_value_type = typename Nested::base_type;

    base_cache_entry() = default;
    base_cache_entry(const base_cache_entry &) = default;
    base_cache_entry &operator=(const base_cache_entry &) = default;
    base_cache_entry(base_cache_entry &&) = default;
    base_cache_entry &operator=(base_cache_entry &&) = default;
    virtual ~base_cache_entry() = default;

    virtual const value_type &first() const = 0;
    virtual value_type &first() = 0;
    virtual const nested_value_type &second() const = 0;
    virtual nested_value_type &second() = 0;
};

template <typename T>
    requires(!CacheOfAnyType<T>)
class base_cache_entry<T, void> {
public:
    using value_type = T;
    using base_type = base_cache_entry<T, void>;

    base_cache_entry() = default;
    base_cache_entry(const base_cache_entry &) = default;
    base_cache_entry &operator=(const base_cache_entry &) = default;
    base_cache_entry(base_cache_entry &&) = default;
    base_cache_entry &operator=(base_cache_entry &&) = default;
    virtual ~base_cache_entry() = default;

    virtual const value_type *operator->() const = 0;
    virtual value_type *operator->() = 0;

    virtual const value_type &first() const = 0;
    virtual value_type &first() = 0;
};

// Cache entry
template <typename T, typename Nested>
    requires(!CacheOfAnyType<T>) && CacheOfAnyType<Nested>
class cache_entry<T, Nested> : public base_cache_entry<T, Nested> {
public:
    using base_type = base_cache_entry<T, Nested>;

    using value_type = T;
    using nested_value_type = typename Nested::base_type;

    const value_type *operator->() const override { return &data_; }
    value_type *operator->() override { return &data_; }

    const value_type &first() const override { return data_; }
    value_type &first() override { return data_; }
    const nested_value_type &second() const override { return nested_; }
    nested_value_type &second() override { return nested_; }

protected:
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    value_type data_;
    Nested nested_;
};

template <typename T, typename Nested>
    requires CacheOfAnyType<T> && CacheOfAnyType<Nested>
class cache_entry<T, Nested> : public base_cache_entry<T, Nested> {
public:
    using base_type = base_cache_entry<T, Nested>;

    using value_type = T;
    using nested_value_type = typename Nested::base_type;

    const value_type &first() const override { return data_; }
    value_type &first() override { return data_; }
    const nested_value_type &second() const override { return nested_; }
    nested_value_type &second() override { return nested_; }

protected:
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    value_type data_;
    Nested nested_;
};

template <typename T> class cache_entry<T, void> : public base_cache_entry<T, void> {
public:
    using base_type = base_cache_entry<T>;

    using value_type = T;

    const value_type *operator->() const override { return &data_; }
    value_type *operator->() override { return &data_; }

    const value_type &first() const override { return data_; }
    value_type &first() override { return data_; }

protected:
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    value_type data_;
};

template <typename Key, CacheEntry T> class base_cache_store {
public:
    using key_type = Key;
    using value_type = typename T::base_type;

    [[nodiscard]] virtual std::size_t size() const = 0;
    virtual value_type &operator[](const key_type &key) = 0;

    virtual optional_ref<value_type> find(const key_type &key) = 0;
};

template <typename Key, CacheEntry T> class cache_store : public base_cache_store<Key, T> {
public:
    using base_type = base_cache_store<Key, T>;

    using key_type = Key;
    using value_type = typename T::base_type;

    value_type &operator[](const key_type &key) override { return data_[key]; }

    [[nodiscard]] std::size_t size() const override { return data_.size(); }

    optional_ref<value_type> find(const key_type &key) override
    {
        auto it = data_.find(key);
        if (it == data_.end()) {
            return std::nullopt;
        }
        return it->second;
    }

protected:
    std::unordered_map<key_type, T> data_;
};

template <CacheEntry T> class sequential_cache_store : public base_cache_store<std::size_t, T> {
public:
    using base_type = base_cache_store<std::size_t, T>;

    using key_type = std::size_t;
    using value_type = typename T::base_type;

    [[nodiscard]] std::size_t size() const override { return data_.size(); }

    value_type &operator[](const key_type &key) override
    {
        if (data_.size() <= key) {
            data_.resize(key + 1);
        }

        return data_[key];
    }

    optional_ref<value_type> find(const key_type &key) override { return operator[](key); }

protected:
    std::vector<T> data_;
};

} // namespace ddwaf
