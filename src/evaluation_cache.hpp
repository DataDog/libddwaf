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

// Base cache entry
template <typename T, typename Nested>
    requires CacheStore<Nested>
class base_cache_entry<T, Nested> {
public:
    using value_type = T;
    using base_type = base_cache_entry<T, Nested>;

    using nested_key_type = typename Nested::key_type;
    using nested_base_type = typename Nested::base_type;

    base_cache_entry() = default;
    base_cache_entry(const base_cache_entry &) = default;
    base_cache_entry &operator=(const base_cache_entry &) = default;
    base_cache_entry(base_cache_entry &&) = default;
    base_cache_entry &operator=(base_cache_entry &&) = default;
    virtual ~base_cache_entry() = default;

    virtual const value_type *operator->() const = 0;
    virtual value_type *operator->() = 0;
    virtual value_type &operator*() = 0;
    virtual value_type *get() = 0;

    [[nodiscard]] virtual std::size_t size() const = 0;
    virtual nested_base_type &operator[](const nested_key_type &key) = 0;
};

template <typename T, typename Nested>
    requires(!CacheStore<Nested>)
class base_cache_entry<T, Nested> {
public:
    using value_type = T;
    using base_type = base_cache_entry<T, Nested>;

    using nested_base_type = typename Nested::base_type;

    base_cache_entry() = default;
    base_cache_entry(const base_cache_entry &) = default;
    base_cache_entry &operator=(const base_cache_entry &) = default;
    base_cache_entry(base_cache_entry &&) = default;
    base_cache_entry &operator=(base_cache_entry &&) = default;
    virtual ~base_cache_entry() = default;

    virtual const value_type *operator->() const = 0;
    virtual value_type *operator->() = 0;
    virtual value_type &operator*() = 0;
    virtual value_type *get() = 0;

    virtual nested_base_type &nested_cache() = 0;
};

template <typename T> class base_cache_entry<T, void> {
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
    virtual value_type &operator*() = 0;
    virtual value_type *get() = 0;
};

// Cache entry
template <typename T, typename Nested>
    requires CacheStore<Nested>
class cache_entry<T, Nested> : public base_cache_entry<T, Nested> {
public:
    using value_type = T;
    using base_type = base_cache_entry<T, Nested>;

    using nested_key_type = typename Nested::key_type;
    using nested_base_type = typename Nested::base_type;

    const value_type *operator->() const override { return &data_; }
    value_type *operator->() override { return &data_; }
    value_type &operator*() override { return data_; }
    value_type *get() override { return &data_; }

    [[nodiscard]] std::size_t size() const override { return store_.size(); }
    nested_base_type &operator[](const nested_key_type &key) override { return store_[key]; }

protected:
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    value_type data_;
    Nested store_;
};

template <typename T, typename Nested>
    requires(!CacheStore<Nested>)
class cache_entry<T, Nested> : public base_cache_entry<T, Nested> {
public:
    using value_type = T;
    using base_type = base_cache_entry<T, Nested>;

    using nested_base_type = typename Nested::base_type;

    const value_type *operator->() const override { return &data_; }
    value_type *operator->() override { return &data_; }
    value_type &operator*() override { return data_; }
    value_type *get() override { return &data_; }

    nested_base_type &nested_cache() override { return nested_; }

protected:
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    value_type data_;
    Nested nested_;
};

template <typename T> class cache_entry<T, void> : public base_cache_entry<T, void> {
public:
    using value_type = T;
    using base_type = base_cache_entry<T>;

    const value_type *operator->() const override { return &data_; }
    value_type *operator->() override { return &data_; }
    value_type &operator*() override { return data_; }
    value_type *get() override { return &data_; }

protected:
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    value_type data_;
};

template <typename T> class cache_entry_ref<T, void> : public base_cache_entry<T, void> {
public:
    using value_type = T;
    using base_type = base_cache_entry<T>;

    explicit cache_entry_ref(cache_entry<T> &ref) : data_(*ref) {}

    const value_type *operator->() const override { return &data_; }
    value_type *operator->() override { return &data_; }
    value_type &operator*() override { return data_; }
    value_type *get() override { return &data_; }

protected:
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    value_type &data_;
};

template <typename Key, CacheEntry T> class cache_store {
public:
    using key_type = Key;
    using base_type = typename T::base_type;

    base_type &operator[](const key_type &key) { return data_[key]; }

    [[nodiscard]] std::size_t size() const { return data_.size(); }

    optional_ref<base_type &> find(const key_type &key)
    {
        auto it = data_.find(key);
        if (it == data_.end()) {
            return std::nullopt;
        }
        return {it->second};
    }

protected:
    std::unordered_map<key_type, T> data_;
};

template <CacheEntry T> class sequential_cache_store {
public:
    using key_type = std::size_t;
    using base_type = typename T::base_type;

    [[nodiscard]] std::size_t size() const { return data_.size(); }

    base_type &operator[](std::size_t i)
    {
        if (data_.size() <= i) {
            data_.resize(i + 1);
        }

        return data_[i];
    }

protected:
    std::vector<T> data_;
};

} // namespace ddwaf
