// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <cstddef>
#include <cstring>
#include <memory_resource>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <type_traits>

#include "utils.hpp"

namespace ddwaf {

enum class object_type : uint8_t {
    invalid = 0x00, // 0b00000000
    null = 0x01,    // 0b00000001
    // invalid == (type & 0xfe) == 0
    boolean = 0x02,      // 0b00000010
    int64 = 0x03,        // 0b00000011
    uint64 = 0x04,       // 0b00000100
    float64 = 0x05,      // 0b00000101
    string = 0x10,       // 0b00010000
    const_string = 0x11, // 0b00010001
    small_string = 0x12, // 0b00010010
    scalar = 0x1E,
    // string == (type & 0x10) != 0
    // scalar == (type & 0x1e) != 0
    array = 0x20, // 0b00100000
    map = 0x40,   // 0b01000000
    container = 0xE0,
    valid = 0xFE,
    // container == (type & 0xE0) != 0
};

template <typename T> object_type operator&(object_type left, T right)
{
    static_assert(std::is_same_v<T, object_type> || std::is_integral_v<T>);

    using utype = std::underlying_type_t<object_type>;
    return static_cast<object_type>(static_cast<utype>(left) & static_cast<utype>(right));
}

template <typename T> auto operator<=>(object_type left, T right)
{
    static_assert(std::is_same_v<T, object_type> || std::is_integral_v<T>);

    using utype = std::underlying_type_t<object_type>;
    return static_cast<utype>(left) <=> static_cast<utype>(right);
}

template <typename T> bool operator==(object_type left, T right)
{
    static_assert(std::is_same_v<T, object_type> || std::is_integral_v<T>);

    using utype = std::underlying_type_t<object_type>;
    return static_cast<utype>(left) == static_cast<utype>(right);
}

namespace detail {
constexpr std::size_t OBJ_SSTR_SIZE = 11;

struct object_kv;
struct [[gnu::packed, gnu::may_alias]] object {
    union [[gnu::packed]] {
        bool b8;
        uint64_t u64;
        int64_t i64;
        double f64;
        object_kv *map;
        object *array;
        char *str;
        std::array<char, OBJ_SSTR_SIZE> sstr;
        const char *cstr;
    } via;
    object_type type{object_type::invalid};
    union [[gnu::packed]] {
        struct [[gnu::packed]] {
            uint16_t capacity{0};
            uint16_t size{0};
        };
        uint32_t length;
    };
};

struct [[gnu::packed]] object_kv {
    detail::object key;
    detail::object val;
};

static_assert(sizeof(object) == 16);
static_assert(sizeof(object_kv) == 32);

} // namespace detail

class owned_object;
class borrowed_object;
class object_view;
class array_object_view;
class map_object_view;

class borrowed_object {
public:
    static borrowed_object from_native(detail::object *object) { return {object, nullptr}; }

    borrowed_object emplace_back(owned_object &&value);
    borrowed_object emplace(std::string_view key, owned_object &&value);

    detail::object *ptr() { return obj_; }

protected:
    borrowed_object() = default;
    borrowed_object(detail::object *obj, std::pmr::memory_resource *alloc)
        : obj_(obj), alloc_(alloc)
    {}

    detail::object *obj_{nullptr};
    std::pmr::memory_resource *alloc_{nullptr};

    friend class owned_object;
};

class owned_object {
public:
    owned_object() = default;

    ~owned_object() { object_free(obj_, alloc_); }

    owned_object(const owned_object &) = delete;
    owned_object(owned_object &&) = default;
    owned_object &operator=(const owned_object &) = delete;
    owned_object &operator=(owned_object &&) = default;

    static owned_object from_native(
        detail::object *source, std::pmr::memory_resource *alloc = std::pmr::new_delete_resource())
    {
        return {*source, alloc};
    }

    detail::object to_native()
    {
        detail::object aux = obj_;
        obj_ = detail::object{};
        return aux;
    }

    static owned_object make_invalid() { return {}; }

    static owned_object make_null()
    {
        detail::object obj{};
        obj.type = object_type::null;
        return {obj, nullptr};
    }

    static owned_object make_boolean(bool value)
    {
        detail::object obj{};
        obj.via.b8 = value;
        obj.type = object_type::boolean;
        return {obj, nullptr};
    }

    static owned_object make_signed(int64_t value)
    {
        detail::object obj{};
        obj.via.i64 = value;
        obj.type = object_type::int64;
        return {obj, nullptr};
    }

    static owned_object make_unsigned(uint64_t value)
    {
        detail::object obj{};
        obj.via.u64 = value;
        obj.type = object_type::uint64;
        return {obj, nullptr};
    }

    static owned_object make_float(double value)
    {
        detail::object obj{};
        obj.via.f64 = value;
        obj.type = object_type::float64;
        return {obj, nullptr};
    }

    /*static owned_object make_string(char *str, std::size_t len,*/
    /*std::pmr::memory_resource *alloc = std::pmr::new_delete_resource())*/
    /*{*/
    /*// TODO check max string limit*/
    /*detail::object obj{};*/
    /*obj.via.str = str;*/
    /*obj.length = len;*/
    /*obj.type = object_type::string;*/
    /*return {obj, alloc};*/
    /*}*/

    static owned_object make_string(const char *str, std::size_t len)
    {
        // TODO check max string limit
        detail::object obj{};
        obj.via.cstr = str;
        obj.length = len;
        obj.type = object_type::const_string;
        return {obj, nullptr};
    }

    static owned_object make_string(
        std::string_view str, std::pmr::memory_resource *alloc = std::pmr::new_delete_resource())
    {
        // TODO check max string limit
        detail::object obj{};
        if (str.size() <= detail::OBJ_SSTR_SIZE) {
            obj.type = object_type::small_string;
            std::memcpy(&obj.via.sstr, str.data(), str.size());
        } else {
            obj.type = object_type::string;
            obj.via.str = static_cast<char *>(alloc->allocate(sizeof(char) * str.size()));
            std::memcpy(obj.via.str, str.data(), str.size());
        }
        obj.length = str.size();
        return {obj, alloc};
    }

    static owned_object make_array(
        std::size_t capacity, std::pmr::memory_resource *alloc = std::pmr::new_delete_resource())
    {
        // TODO check capacity limit
        detail::object obj{};
        obj.via.array = static_cast<detail::object *>(
            alloc->allocate(sizeof(detail::object) * capacity, alignof(detail::object)));
        obj.type = object_type::array;
        obj.capacity = capacity;
        obj.size = 0;
        return {obj, alloc};
    }

    static owned_object make_map(
        std::size_t capacity, std::pmr::memory_resource *alloc = std::pmr::new_delete_resource())
    {
        detail::object obj{};
        // TODO check capacity limit
        obj.via.map = static_cast<detail::object_kv *>(
            alloc->allocate(sizeof(detail::object_kv) * capacity, alignof(detail::object_kv)));
        obj.type = object_type::map;
        obj.capacity = capacity;
        obj.size = 0;
        return {obj, alloc};
    }

    detail::object move()
    {
        detail::object copy = obj_;
        obj_.type = object_type::invalid;
        return copy;
    }

    borrowed_object emplace_back(owned_object &&value)
    {
        // TODO check for allocator compatibility
        if (obj_.type != object_type::array || obj_.size == obj_.capacity) {
            return {};
        }

        auto &current = obj_.via.array[obj_.size++];
        current = value.move();
        return {&current, alloc_};
    }

    borrowed_object emplace(std::string_view key, owned_object &&value)
    {
        // TODO check for allocator compatibility
        if (obj_.type != object_type::map || obj_.size == obj_.capacity) {
            return {};
        }

        auto &current = obj_.via.map[obj_.size++];
        current.key = make_string(key).move();
        current.val = value.move();

        return {&current.val, alloc_};
    }

    [[nodiscard]] object_view view();

protected:
    owned_object(detail::object obj, std::pmr::memory_resource *alloc) : obj_(obj), alloc_(alloc) {}

    // NOLINTNEXTLINE(misc-no-recursion)
    static void object_free(detail::object &obj, std::pmr::memory_resource *alloc)
    {
        if (obj.type == object_type::array) {
            for (std::size_t i = 0; i < obj.size; ++i) { object_free(obj.via.array[i], alloc); }
            alloc->deallocate(
                obj.via.array, obj.capacity * sizeof(detail::object), alignof(detail::object));
        } else if (obj.type == object_type::map) {
            for (std::size_t i = 0; i < obj.size; ++i) {
                object_free(obj.via.map[i].key, alloc);
                object_free(obj.via.map[i].val, alloc);
            }
            alloc->deallocate(
                obj.via.map, obj.capacity * sizeof(detail::object_kv), alignof(detail::object_kv));
        } else if (obj.type == object_type::string) {
            alloc->deallocate(obj.via.str, obj.length * sizeof(char));
        }
    }

    detail::object obj_;
    std::pmr::memory_resource *alloc_{std::pmr::new_delete_resource()};
};

inline borrowed_object borrowed_object::emplace_back(owned_object &&value)
{
    // TODO check for allocator compatibility
    if (obj_->type != object_type::array || obj_->size == obj_->capacity) {
        return {};
    }

    auto &current = obj_->via.array[obj_->size++];
    current = value.move();
    return {&current, alloc_};
}

inline borrowed_object borrowed_object::emplace(std::string_view key, owned_object &&value)
{
    // TODO check for allocator compatibility
    if (obj_->type != object_type::map || obj_->size == obj_->capacity) {
        return {};
    }

    auto &current = obj_->via.map[obj_->size++];
    current.key = owned_object::make_string(key).move();
    current.val = value.move();

    return {&current.val, alloc_};
}

class object_view {
public:
    object_view() = default;
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    object_view(const detail::object *underlying_object) : obj_(underlying_object) {}
    ~object_view() = default;
    object_view(const object_view &) = default;
    object_view(object_view &&) = default;
    object_view &operator=(const object_view &) = default;
    object_view &operator=(object_view &&) = default;

    [[nodiscard]] object_type type() const { return obj_->type; }
    [[nodiscard]] std::size_t size() const { return static_cast<std::size_t>(obj_->size); }
    [[nodiscard]] std::size_t length() const { return static_cast<std::size_t>(obj_->length); }
    [[nodiscard]] std::size_t capacity() const { return static_cast<std::size_t>(obj_->capacity); }
    [[nodiscard]] bool empty() const { return (is_container() ? size() : length()) > 0; }

    [[nodiscard]] bool is_valid() const { return (obj_->type & object_type::valid) != 0; }
    [[nodiscard]] bool is_invalid() const { return (obj_->type & object_type::valid) == 0; }
    [[nodiscard]] bool is_container() const { return (obj_->type & object_type::container) != 0; }
    [[nodiscard]] bool is_scalar() const { return (obj_->type & object_type::container) != 0; }

    bool operator==(const object_view other) const { return ptr() == other.ptr(); }

    [[nodiscard]] const detail::object *ptr() const { return obj_; }

    std::optional<std::pair<object_view, object_view>> at(std::size_t index)
    {
        // TODO add requires
        if (index > size()) {
            return std::nullopt;
        }
        if (type() == object_type::map) {
            auto &slot = obj_->via.map[index];
            return {{object_view{&slot.key}, object_view{&slot.val}}};
        }

        if (type() == object_type::array) {
            auto &slot = obj_->via.array[index];
            return {{object_view{}, object_view{&slot}}};
        }
    }

    std::pair<object_view, object_view> at_unchecked(std::size_t index)
    {
        if (type() == object_type::map) {
            auto &slot = obj_->via.map[index];
            return {object_view{&slot.key}, object_view{&slot.val}};
        }

        if (type() == object_type::array) {
            auto &slot = obj_->via.array[index];
            return {object_view{}, object_view{&slot}};
        }
        return {};
    }
    template <typename T> std::optional<T> as_optional() const noexcept
    {
        if constexpr (std::is_same_v<T, const object_view *>) {
            return this;
        }

        if constexpr (std::is_same_v<T, const detail::object *>) {
            return obj_;
        }

        if constexpr (std::is_same_v<T, const char *>) {
            if (type() == object_type::string) {
                return T{obj_->via.str};
            }
            if (type() == object_type::const_string) {
                return T{obj_->via.cstr};
            }
            if (type() == object_type::small_string) {
                return T{obj_->via.sstr.data()};
            }
        }

        if constexpr (std::is_same_v<T, std::string_view> || std::is_same_v<T, std::string>) {
            if (type() == object_type::string) {
                return T{obj_->via.str, length()};
            }
            if (type() == object_type::const_string) {
                return T{obj_->via.cstr, length()};
            }
            if (type() == object_type::small_string) {
                return T{obj_->via.sstr.data(), length()};
            }
        }

        if constexpr (std::is_same_v<T, uint64_t> || std::is_same_v<T, unsigned>) {
            using limits = std::numeric_limits<T>;
            if (type() == object_type::uint64 && obj_->via.u64 <= limits::max()) {
                return static_cast<T>(obj_->via.u64);
            }
        }

        if constexpr (std::is_same_v<T, int64_t> || std::is_same_v<T, int>) {
            using limits = std::numeric_limits<T>;
            if (type() == object_type::int64 && obj_->via.i64 >= limits::min() &&
                obj_->via.i64 <= limits::max()) {
                return static_cast<T>(obj_->via.i64);
            }
        }

        if constexpr (std::is_floating_point_v<T>) {
            using limits = std::numeric_limits<T>;
            if (type() == object_type::float64 && obj_->via.f64 >= limits::min() &&
                obj_->via.f64 <= limits::max()) {
                return static_cast<T>(obj_->via.f64);
            }
        }

        if constexpr (std::is_same_v<T, bool>) {
            if (type() == object_type::boolean) {
                return static_cast<T>(obj_->via.b8);
            }
        }

        return std::nullopt;
    }

    template <typename T> T as();
    template <typename T> [[nodiscard]] T as_nothrow() const noexcept
    {
        if constexpr (std::is_same_v<T, const object_view *>) {
            return this;
        }

        if constexpr (std::is_same_v<T, const detail::object *>) {
            return obj_;
        }

        if constexpr (std::is_same_v<T, const char *>) {
            if (type() == object_type::string) {
                return T{obj_->via.str};
            }
            if (type() == object_type::const_string) {
                return T{obj_->via.cstr};
            }
            if (type() == object_type::small_string) {
                return T{obj_->via.sstr.data()};
            }
        }

        if constexpr (std::is_same_v<T, std::string_view> || std::is_same_v<T, std::string>) {
            if (type() == object_type::string) {
                return T{obj_->via.str, length()};
            }
            if (type() == object_type::const_string) {
                return T{obj_->via.cstr, length()};
            }
            if (type() == object_type::small_string) {
                return T{obj_->via.sstr.data(), length()};
            }
        }

        if constexpr (std::is_same_v<T, uint64_t> || std::is_same_v<T, unsigned>) {
            using limits = std::numeric_limits<T>;
            if (type() == object_type::uint64 && obj_->via.u64 <= limits::max()) {
                return static_cast<T>(obj_->via.u64);
            }
        }

        if constexpr (std::is_same_v<T, int64_t> || std::is_same_v<T, int>) {
            using limits = std::numeric_limits<T>;
            if (type() == object_type::int64 && obj_->via.i64 >= limits::min() &&
                obj_->via.i64 <= limits::max()) {
                return static_cast<T>(obj_->via.i64);
            }
        }

        if constexpr (std::is_floating_point_v<T>) {
            using limits = std::numeric_limits<T>;
            if (type() == object_type::float64 && obj_->via.f64 >= limits::min() &&
                obj_->via.f64 <= limits::max()) {
                return static_cast<T>(obj_->via.f64);
            }
        }

        if constexpr (std::is_same_v<T, bool>) {
            if (type() == object_type::boolean) {
                return static_cast<T>(obj_->via.b8);
            }
        }

        return {};
    }

    template <typename T>
    [[nodiscard]] T as() const
        requires std::is_same_v<T, std::string>
    {
        switch (type()) {
        case object_type::string:
        case object_type::const_string:
        case object_type::small_string:
            return as<std::string>();
        case object_type::boolean:
            return ddwaf::to_string<std::string>(obj_->via.b8);
        case object_type::uint64:
            return ddwaf::to_string<std::string>(obj_->via.u64);
        case object_type::int64:
            return ddwaf::to_string<std::string>(obj_->via.i64);
        case object_type::float64:
            return ddwaf::to_string<std::string>(obj_->via.f64);
        default:
            break;
        }
        return {};
    }

protected:
    friend class map_object_view;
    friend class array_object_view;

    const detail::object *obj_{nullptr};
};

template <> inline std::string_view object_view::as<std::string_view>()
{
    if (type() == object_type::string) {
        return {obj_->via.str, length()};
    }
    if (type() == object_type::const_string) {
        return {obj_->via.cstr, length()};
    }
    if (type() == object_type::small_string) {
        return {obj_->via.sstr.data(), length()};
    }
    [[unlikely]] throw std::runtime_error("object_view not a string");
}

class array_object_view {
public:
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    array_object_view(const detail::object *underlying_object) : obj_(underlying_object)
    {
        if (obj_->type != object_type::array) {
            throw std::invalid_argument("array_object_view initialised with incompatible object");
        }
    }

    ~array_object_view() = default;
    array_object_view(const array_object_view &) = default;
    array_object_view(array_object_view &&) = default;
    array_object_view &operator=(const array_object_view &) = default;
    array_object_view &operator=(array_object_view &&) = default;

    [[nodiscard]] std::size_t size() const { return static_cast<std::size_t>(obj_->size); }
    [[nodiscard]] std::size_t capacity() const { return static_cast<std::size_t>(obj_->capacity); }
    [[nodiscard]] bool empty() const { return size() > 0; }

    [[nodiscard]] const detail::object *ptr() const { return obj_; }

    object_view operator[](std::size_t index) const { return {&obj_->via.array[index]}; }

    object_view at(std::size_t index)
    {
        if (index > size()) {
            throw std::out_of_range("at index out of range");
        }
        return &obj_->via.array[index];
    }

    object_view at_unchecked(std::size_t index) { return &obj_->via.array[index]; }

    class iterator {
    public:
        explicit iterator(array_object_view &ov, size_t index = 0)
            : current_(ov.obj_->via.array), end_(ov.obj_->via.array + ov.size())
        {
            if (index > ov.size()) {
                throw std::out_of_range("iterator beyond array end");
            }
            current_ += index;
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

    iterator begin() { return iterator{*this, 0}; }

    iterator end() { return iterator{*this, obj_->size}; }

protected:
    const detail::object *obj_;
};

class map_object_view {
public:
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    map_object_view(const detail::object *underlying_object) : obj_(underlying_object)
    {
        if (obj_->type != object_type::map) {
            throw std::invalid_argument("map_object_view initialised with incompatible object");
        }
    }

    ~map_object_view() = default;
    map_object_view(const map_object_view &) = default;
    map_object_view(map_object_view &&) = default;
    map_object_view &operator=(const map_object_view &) = default;
    map_object_view &operator=(map_object_view &&) = default;

    [[nodiscard]] std::size_t size() const { return static_cast<std::size_t>(obj_->size); }
    [[nodiscard]] std::size_t capacity() const { return static_cast<std::size_t>(obj_->capacity); }
    [[nodiscard]] bool empty() const { return size() > 0; }

    [[nodiscard]] const detail::object *ptr() const { return obj_; }

    [[nodiscard]] std::optional<object_view> at(std::string_view key) const
    {
        for (std::size_t i = 0; i < size(); ++i) {
            auto current_key = object_view{&obj_->via.map[i].key}.as<std::string_view>();
            if (current_key == key) {
                return {&obj_->via.map[i].val};
            }
        }
        return std::nullopt;
    }

    template <typename KeyType = std::string_view>
    std::optional<std::pair<KeyType, object_view>> at(std::size_t index)
    {
        // TODO add requires
        if (index > size()) {
            return std::nullopt;
        }
        auto &slot = obj_->via.map[index];
        return {object_view{&slot.key}.as<KeyType>(), object_view{&slot.val}};
    }

    std::pair<object_view, object_view> at_unchecked(std::size_t index)
    {
        auto &slot = obj_->via.map[index];
        return {object_view{&slot.key}, object_view{&slot.val}};
    }

    class iterator {
    public:
        explicit iterator(map_object_view &ov, size_t index = 0)
            : current_(ov.obj_->via.map), end_(ov.obj_->via.map + ov.size())
        {
            /*            if (index >= ov.size()) {*/
            /*throw std::out_of_range("iterator beyond map end");*/
            /*}*/
            current_ += index;
        }

        bool operator!=(const iterator &rhs) const noexcept { return current_ != rhs.current_; }

        [[nodiscard]] std::string_view key() const noexcept
        {
            if (current_ == end_) {
                return {};
            }
            object_view key_view = &current_->key;
            return key_view.as_nothrow<std::string_view>();
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
    const detail::object *obj_;
};

inline object_view owned_object::view() { return {&obj_}; }

template <> inline array_object_view object_view::as<array_object_view>()
{
    if (type() != object_type::array) {
        [[unlikely]] throw std::runtime_error("object_view not an array");
    }
    return {obj_};
}

template <> inline map_object_view object_view::as<map_object_view>()
{
    if (type() != object_type::map) {
        [[unlikely]] throw std::runtime_error("object_view not a map");
    }
    return {obj_};
}

} // namespace ddwaf

namespace std {

template <> struct hash<ddwaf::object_view> {
    auto operator()(const ddwaf::object_view &obj) const
    {
        return std::hash<const void *>{}(static_cast<const void *>(obj.ptr()));
    }
};

} // namespace std
