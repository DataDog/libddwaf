// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <cstddef>
#include <cstring>
#include <iostream>
#include <optional>
#include <string_view>
#include <type_traits>

#include "object.hpp"
#include "object_type.hpp"

namespace ddwaf {

template <typename T> struct converter;

class object_view {
public:
    class map;
    class array;

    object_view() = default;
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    object_view(const owned_object &obj) : obj_(obj.ptr()) {}
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    object_view(const borrowed_object &obj) : obj_(obj.ptr()) {}
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    object_view(const detail::object *underlying_object) : obj_(underlying_object) {}
    ~object_view() = default;
    object_view(const object_view &) = default;
    object_view(object_view &&) = default;
    object_view &operator=(const object_view &) = default;
    object_view &operator=(object_view &&) = default;

    [[nodiscard]] bool has_value() const noexcept { return obj_ != nullptr; }

    [[nodiscard]] object_type type() const noexcept
    {
        if (obj_ == nullptr) {
            [[unlikely]] return object_type::invalid;
        }
        return obj_->type;
    }
    [[nodiscard]] std::size_t size() const noexcept
    {
        if (!is_container()) {
            [[unlikely]] return 0;
        }
        return static_cast<std::size_t>(obj_->size);
    }
    [[nodiscard]] std::size_t capacity() const noexcept
    {
        if (!is_container()) {
            [[unlikely]] return 0;
        }
        return static_cast<std::size_t>(obj_->capacity);
    }
    [[nodiscard]] std::size_t length() const noexcept
    {
        if (!is_string()) {
            [[unlikely]] return 0;
        }
        return static_cast<std::size_t>(obj_->length);
    }
    [[nodiscard]] bool empty() const noexcept { return (is_container() ? size() : length()) == 0; }
    template <typename T> [[nodiscard]] bool is() const noexcept
    {
        return obj_ != nullptr && is_compatible_type<T>(obj_->type);
    }
    [[nodiscard]] bool is_valid() const noexcept
    {
        return obj_ != nullptr && obj_->type != object_type::invalid;
    }
    [[nodiscard]] bool is_invalid() const noexcept
    {
        return obj_ == nullptr || obj_->type == object_type::invalid;
    }
    [[nodiscard]] bool is_container() const noexcept
    {
        return obj_ != nullptr && (obj_->type & container_object_type) != 0;
    }
    [[nodiscard]] bool is_scalar() const noexcept
    {
        return obj_ != nullptr && (obj_->type & scalar_object_type) != 0;
    }
    [[nodiscard]] bool is_string() const noexcept
    {
        return obj_ != nullptr && (obj_->type & object_type::string) != 0;
    }
    bool operator==(const object_view other) const { return ptr() == other.ptr(); }
    bool operator!=(const object_view other) const { return ptr() != other.ptr(); }

    [[nodiscard]] const detail::object *ptr() const { return obj_; }

    [[nodiscard]] std::pair<object_view, object_view> at(std::size_t index) const noexcept
    {
        if (!is_container() || index > size()) {
            [[unlikely]] return {};
        }
        return at_unchecked(index);
    }

    [[nodiscard]] std::pair<object_view, object_view> at_unchecked(std::size_t index) const noexcept
    {
        if (type() == object_type::map) {
            auto &slot = obj_->via.map[index];
            return {object_view{&slot.key}, object_view{&slot.val}};
        }

        auto &slot = obj_->via.array[index];
        return {object_view{}, object_view{&slot}};
    }

    template <typename T> [[nodiscard]] std::optional<T> as() const noexcept
    {
        if (!is_compatible_type<T>(type())) {
            return std::nullopt;
        }
        return as_unchecked<T>();
    }

    template <typename T>
    [[nodiscard]] std::optional<T> as() const noexcept
        requires std::is_same_v<T, object_view>
    {
        return {*this};
    }

    template <typename T>
    [[nodiscard]] T as_unchecked() const noexcept
        requires std::is_same_v<T, object_view>
    {
        return {obj_};
    }

    template <typename T>
    [[nodiscard]] T as_unchecked() const noexcept
        requires std::is_same_v<T, bool>
    {
        return obj_->via.b8;
    }

    template <typename T>
    [[nodiscard]] T as_unchecked() const noexcept
        requires std::is_integral_v<T> && std::is_signed_v<T> && (!std::is_same_v<T, bool>)
    {
        return static_cast<T>(obj_->via.i64);
    }

    template <typename T>
    [[nodiscard]] T as_unchecked() const noexcept
        requires std::is_unsigned_v<T> && (!std::is_same_v<T, bool>)
    {
        return static_cast<T>(obj_->via.u64);
    }

    template <typename T>
    [[nodiscard]] T as_unchecked() const noexcept
        requires std::is_floating_point_v<T>
    {
        return static_cast<T>(obj_->via.f64);
    }

    template <typename T>
    [[nodiscard]] T as_unchecked() const noexcept
        requires std::is_same_v<T, std::string> || std::is_same_v<T, std::string_view>
    {
        if (type() == object_type::const_string) {
            return {obj_->via.cstr, length()};
        }
        if (type() == object_type::small_string) {
            return {obj_->via.sstr.data(), length()};
        }
        return {obj_->via.str, length()};
    }

    template <typename T>
    [[nodiscard]] T as_unchecked() const noexcept
        requires std::is_same_v<T, const char *>
    {
        if (type() == object_type::const_string) {
            return obj_->via.cstr;
        }
        if (type() == object_type::small_string) {
            return obj_->via.sstr.data();
        }
        return obj_->via.str;
    }

    template <typename T> T convert() const { return converter<T>{*this}(); }

    /*    class iterator {*/
    /*public:*/
    /*iterator() = default;*/

    /*// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)*/
    /*explicit iterator(const detail::object *obj, std::size_t index = 0,*/
    /*std::size_t max_size = std::numeric_limits<uint16_t>::max())*/
    /*: internal_(obj, index, max_size)*/
    /*{}*/

    /*[[nodiscard]] bool is_valid() const noexcept { return internal_.index < internal_.size; }*/

    /*[[nodiscard]] object_type type() const noexcept*/
    /*{*/
    /*if (internal_.type == iterator_type::array) {*/
    /*return object_type::array;*/
    /*}*/
    /*if (internal_.type == iterator_type::map) {*/
    /*return object_type::map;*/
    /*}*/

    /*return object_type::invalid;*/
    /*}*/

    /*bool operator!=(const iterator &rhs) const noexcept*/
    /*{*/
    /*return internal_.type == rhs.internal_.type && internal_.index == rhs.internal_.index &&*/
    /*((internal_.type == iterator_type::map &&*/
    /*internal_.via.kv_ptr == rhs.internal_.via.kv_ptr) ||*/
    /*(internal_.type == iterator_type::array &&*/
    /*internal_.via.ptr == rhs.internal_.via.ptr));*/
    /*}*/

    /*std::pair<object_view, object_view> operator*() const noexcept*/
    /*{*/
    /*if (internal_.index < internal_.size) {*/
    /*if (internal_.type == iterator_type::array) {*/
    /*return {{}, &internal_.via.ptr[internal_.index]};*/
    /*}*/

    /*if (internal_.type == iterator_type::map) {*/
    /*const auto &kv = internal_.via.kv_ptr[internal_.index];*/
    /*return {&kv.key, &kv.val};*/
    /*}*/
    /*}*/

    /*[[unlikely]] return {};*/
    /*}*/

    /*[[nodiscard]] object_view key() const noexcept*/
    /*{*/
    /*if (internal_.index < internal_.size && internal_.type == iterator_type::map) {*/
    /*std::cout << "We're here\n";*/
    /*return &internal_.via.kv_ptr[internal_.index].key;*/
    /*}*/

    /*[[unlikely]] return {};*/
    /*}*/

    /*[[nodiscard]] object_view value() const noexcept*/
    /*{*/
    /*if (internal_.index < internal_.size) {*/
    /*if (internal_.type == iterator_type::array) {*/
    /*return &internal_.via.ptr[internal_.index];*/
    /*}*/

    /*if (internal_.type == iterator_type::map) {*/
    /*return &internal_.via.kv_ptr[internal_.index].val;*/
    /*}*/
    /*}*/

    /*[[unlikely]] return {};*/
    /*}*/

    /*[[nodiscard]] std::size_t index() const noexcept*/
    /*{*/
    /*return static_cast<std::size_t>(internal_.index);*/
    /*}*/

    /*[[nodiscard]] std::size_t size() const noexcept*/
    /*{*/
    /*return static_cast<std::size_t>(internal_.size);*/
    /*}*/

    /*iterator &operator++() noexcept*/
    /*{*/
    /*if (internal_.index < internal_.size) {*/
    /*++internal_.index;*/
    /*}*/
    /*return *this;*/
    /*}*/

    /*iterator operator-(std::size_t index) const noexcept*/
    /*{*/
    /*if (internal_.index < index) {*/
    /*return {};*/
    /*}*/

    /*iterator it = *this;*/
    /*it.internal_.index -= index;*/
    /*return it;*/
    /*}*/

    /*iterator &operator--() noexcept*/
    /*{*/
    /*if (internal_.index > 0) {*/
    /*--internal_.index;*/
    /*}*/
    /*return *this;*/
    /*}*/

    /*protected:*/
    /*enum class iterator_type : uint8_t { invalid, array, map };*/

    /*detail::object_iterator internal_;*/

    /*friend class object_view;*/
    /*};*/

    /*iterator begin(std::size_t max_size)*/
    /*{*/
    /*if (obj_ == nullptr) {*/
    /*return {};*/
    /*}*/
    /*return iterator{obj_, 0, max_size};*/
    /*}*/
    /*iterator end()*/
    /*{*/
    /*if (obj_ == nullptr) {*/
    /*return {};*/
    /*}*/
    /*return iterator{obj_, obj_->size};*/
    /*}*/

    class array {
    public:
        array() = default;
        ~array() = default;
        array(const array &) = default;
        array(array &&) = default;
        array &operator=(const array &) = default;
        array &operator=(array &&) = default;

        [[nodiscard]] std::size_t size() const
        {
            if (obj_ == nullptr) {
                return 0;
            }
            return static_cast<std::size_t>(obj_->size);
        }
        [[nodiscard]] std::size_t capacity() const
        {
            if (obj_ == nullptr) {
                return 0;
            }
            return static_cast<std::size_t>(obj_->capacity);
        }
        [[nodiscard]] bool empty() const { return size() == 0; }

        [[nodiscard]] const detail::object *ptr() const { return obj_; }

        [[nodiscard]] object_view at(std::size_t index) const noexcept
        {
            if (index >= size()) {
                [[unlikely]] return {};
            }
            return at_unchecked(index);
        }

        [[nodiscard]] object_view at_unchecked(std::size_t index) const noexcept
        {
            if (obj_ == nullptr) {
                return {};
            }
            return &obj_->via.array[index];
        }

        class iterator {
        public:
            iterator() = default;
            explicit iterator(array &ov, size_t index = 0)
                : current_(ov.obj_->via.array), end_(ov.obj_->via.array + ov.size())
            {
                if (index >= ov.size()) {
                    current_ = end_;
                } else {
                    current_ += index;
                }
            }

            bool operator!=(const iterator &rhs) const noexcept { return current_ != rhs.current_; }

            object_view operator*() const noexcept
            {
                if (current_ == end_) {
                    return nullptr;
                }
                return {current_};
            }

            iterator &operator++() noexcept
            {
                if (current_ != end_) {
                    current_++;
                }
                return *this;
            }

        protected:
            detail::object *current_{nullptr};
            detail::object *end_{nullptr};
        };

        iterator begin()
        {
            if (obj_ == nullptr) {
                return {};
            }
            return iterator{*this, 0};
        }
        iterator end()
        {
            if (obj_ == nullptr) {
                return {};
            }
            return iterator{*this, obj_->size};
        }

    protected:
        friend class object_view;

        // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
        explicit array(const detail::object *underlying_object) : obj_(underlying_object) {}

        const detail::object *obj_{nullptr};
    };

    template <typename T>
    [[nodiscard]] std::optional<T> as() const noexcept
        requires std::is_same_v<T, object_view::array>
    {
        if (type() == object_type::array) {
            return std::nullopt;
        }
        return as_unchecked<object_view::array>();
    }

    template <typename T>
    [[nodiscard]] T as_unchecked() const noexcept
        requires std::is_same_v<T, array>
    {
        return T{obj_};
    }

    class map {
    public:
        ~map() = default;
        map(const map &) = default;
        map(map &&) = default;
        map &operator=(const map &) = default;
        map &operator=(map &&) = default;

        [[nodiscard]] std::size_t size() const { return static_cast<std::size_t>(obj_->size); }
        [[nodiscard]] std::size_t capacity() const
        {
            return static_cast<std::size_t>(obj_->capacity);
        }
        [[nodiscard]] bool empty() const { return size() == 0; }

        [[nodiscard]] const detail::object *ptr() const { return obj_; }

        [[nodiscard]] object_view at(std::string_view key) const
        {
            for (std::size_t i = 0; i < size(); ++i) {
                auto current_key = object_view{&obj_->via.map[i].key}.as<std::string_view>();
                if (current_key == key) {
                    return {&obj_->via.map[i].val};
                }
            }
            return {};
        }

        template <typename KeyType = std::string_view>
        std::optional<std::pair<KeyType, object_view>> at(std::size_t index)
            requires std::is_same_v<KeyType, std::string> ||
                     std::is_same_v<KeyType, std::string_view> ||
                     std::is_same_v<KeyType, object_view>
        {
            if (index > size()) {
                [[unlikely]] return {};
            }
            return at_unchecked<KeyType>(index);
        }

        template <typename KeyType = std::string_view>
        std::pair<KeyType, object_view> at_unchecked(std::size_t index)
            requires std::is_same_v<KeyType, std::string> ||
                     std::is_same_v<KeyType, std::string_view> ||
                     std::is_same_v<KeyType, object_view>
        {
            auto &slot = obj_->via.map[index];
            return {object_view{&slot.key}.as_unchecked<KeyType>(), object_view{&slot.val}};
        }

        class iterator {
        public:
            explicit iterator(map &ov, size_t index = 0)
                : current_(ov.obj_->via.map), end_(ov.obj_->via.map + ov.size())
            {
                if (index >= ov.size()) {
                    current_ = end_;
                } else {
                    current_ += index;
                }
            }

            bool operator!=(const iterator &rhs) const noexcept { return current_ != rhs.current_; }

            [[nodiscard]] std::string_view key() const noexcept
            {
                if (current_ == end_) {
                    return {};
                }
                object_view key_view = &current_->key;
                return key_view.as_unchecked<std::string_view>();
            }

            std::pair<std::string_view, object_view> operator*() const noexcept
            {
                if (current_ == end_) {
                    return {{}, nullptr};
                }
                return {key(), value()};
            }

            [[nodiscard]] object_view value() const noexcept
            {
                if (current_ == end_) {
                    return nullptr;
                }
                return {&current_->val};
            }

            iterator &operator++() noexcept
            {
                if (current_ != end_) {
                    current_++;
                }
                return *this;
            }

        protected:
            detail::object_kv *current_{nullptr};
            detail::object_kv *end_{nullptr};
        };

        iterator begin() { return iterator{*this, 0}; }

        iterator end() { return iterator{*this, obj_->size}; }

    protected:
        friend class object_view;

        // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
        explicit map(const detail::object *underlying_object) : obj_(underlying_object) {}

        const detail::object *obj_;
    };

    template <typename T>
    [[nodiscard]] std::optional<T> as() const noexcept
        requires std::is_same_v<T, object_view::map>
    {
        if (type() == object_type::map) {
            return std::nullopt;
        }
        return as_unchecked<object_view::map>();
    }

    template <typename T>
    [[nodiscard]] T as_unchecked() const noexcept
        requires std::is_same_v<T, object_view::map>
    {
        return T{obj_};
    }

protected:
    const detail::object *obj_{nullptr};
};

} // namespace ddwaf
namespace std {

template <> struct hash<ddwaf::object_view> {
    auto operator()(const ddwaf::object_view &obj) const
    {
        return std::hash<const void *>{}(static_cast<const void *>(obj.ptr()));
    }
};

} // namespace std
