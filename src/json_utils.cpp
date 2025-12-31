// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <rapidjson/encodings.h>
#include <rapidjson/error/error.h>
#include <rapidjson/rapidjson.h>
#include <rapidjson/reader.h>
#include <string_view>
#include <utility>
#include <vector>

#include "json_utils.hpp"
#include "memory_resource.hpp"
#include "object.hpp"
#include "pointer.hpp"

namespace ddwaf {

struct string_view_stream {
    using Ch = std::string_view::value_type;

    explicit string_view_stream(std::string_view str) : src(str) {}

    [[nodiscard]] char Peek() const
    {
        if (idx < src.size()) [[unlikely]] {
            return src[idx];
        }
        return '\0';
    }
    char Take()
    {
        if (idx < src.size()) [[unlikely]] {
            return src[idx++];
        }
        return '\0';
    }
    [[nodiscard]] size_t Tell() const { return idx; }

    static char *PutBegin()
    {
        assert(false);
        return nullptr;
    }
    static void Put(Ch /*unused*/) { assert(false); }
    static void Flush() { assert(false); }
    static size_t PutEnd(Ch * /*unused*/)
    {
        assert(false);
        return 0;
    }

    std::string_view src;
    std::size_t idx{0};
};

class object_reader_handler
    : public rapidjson::BaseReaderHandler<rapidjson::UTF8<>, object_reader_handler> {
public:
    explicit object_reader_handler(nonnull_ptr<memory::memory_resource> alloc)
        : alloc_(alloc), root_(owned_object::make_uninit(alloc)),
          key_(owned_object::make_uninit(alloc))
    {
        stack_.reserve(max_depth + 1);
    }
    ~object_reader_handler() = default;
    object_reader_handler(object_reader_handler &&) = delete;
    object_reader_handler(const object_reader_handler &) = delete;
    object_reader_handler &operator=(object_reader_handler &&) = delete;
    object_reader_handler &operator=(const object_reader_handler &) = delete;

    bool Null()
    {
        if (stack_.size() > max_depth) [[unlikely]] {
            return true;
        }

        return emplace(owned_object::make_null());
    }

    bool Bool(bool b)
    {
        if (stack_.size() > max_depth) [[unlikely]] {
            return true;
        }

        return emplace(owned_object::make_boolean(b));
    }

    bool Int(int i)
    {
        if (stack_.size() > max_depth) [[unlikely]] {
            return true;
        }

        return emplace(owned_object::make_signed(i));
    }

    bool Uint(unsigned u)
    {
        if (stack_.size() > max_depth) [[unlikely]] {
            return true;
        }

        return emplace(owned_object::make_unsigned(u));
    }

    bool Int64(int64_t i)
    {
        if (stack_.size() > max_depth) [[unlikely]] {
            return true;
        }

        return emplace(owned_object::make_signed(i));
    }

    bool Uint64(uint64_t u)
    {
        if (stack_.size() > max_depth) [[unlikely]] {
            return true;
        }

        return emplace(owned_object::make_unsigned(u));
    }

    bool Double(double d)
    {
        if (stack_.size() > max_depth) [[unlikely]] {
            return true;
        }

        return emplace(owned_object::make_float(d));
    }

    bool String(const char *str, rapidjson::SizeType length, bool /*copy*/)
    {
        if (stack_.size() > max_depth) [[unlikely]] {
            return true;
        }

        return emplace(owned_object::make_string(str, length, alloc_));
    }

    bool Key(const char *str, rapidjson::SizeType length, bool /*copy*/)
    {
        if (stack_.size() > max_depth) [[unlikely]] {
            return true;
        }

        assert(key_.is_invalid());

        key_ = owned_object::make_string(str, length, alloc_);

        return true;
    }

    bool StartObject()
    {
        if (stack_.size() > max_depth) [[unlikely]] {
            ++depth_skip_count_;
            return true;
        }

        return emplace(owned_object::make_map(0, alloc_));
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    bool EndObject(rapidjson::SizeType /*memberCount*/)
    {
        assert(!stack_.empty());
        depth_skip_count_ -= static_cast<std::size_t>(depth_skip_count_ > 0);
        if (depth_skip_count_ == 0) {
            stack_.pop_back();
        }
        return true;
    }

    bool StartArray()
    {
        if (stack_.size() > max_depth) [[unlikely]] {
            ++depth_skip_count_;
            return true;
        }

        return emplace(owned_object::make_array(0, alloc_));
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    bool EndArray(rapidjson::SizeType /*elementCount*/)
    {
        assert(!stack_.empty());
        depth_skip_count_ -= static_cast<std::size_t>(depth_skip_count_ > 0);
        if (depth_skip_count_ == 0) {
            stack_.pop_back();
        }
        return true;
    }

    owned_object finalize()
    {
        stack_.clear();
        return std::move(root_);
    }

private:
    bool emplace(owned_object &&object)
    {
        try {
            if (stack_.empty()) {
                assert(root_.is_invalid());

                root_ = std::move(object);
                if (root_.is_container()) {
                    stack_.emplace_back(root_);
                    // No need to check the depth limit given that it's larger than 1
                }
            } else {
                auto &container = stack_.back();
                auto child = container.is_map()
                                 ? container.emplace(std::move(key_), std::move(object))
                                 : container.emplace_back(std::move(object));
                if (child.is_container()) {
                    stack_.push_back(child);
                    if (stack_.size() > max_depth) {
                        depth_skip_count_ = 1;
                    }
                }
            }
        } catch (...) {
            return false;
        }

        return true;
    }

    nonnull_ptr<memory::memory_resource> alloc_{memory::get_default_resource()};
    owned_object root_;
    std::vector<borrowed_object> stack_;

    owned_object key_;

    std::size_t depth_skip_count_{0};

    static constexpr std::size_t max_depth = 20;
};

owned_object json_to_object(std::string_view json, nonnull_ptr<memory::memory_resource> alloc)
{
    object_reader_handler handler{alloc};
    string_view_stream ss(json);

    rapidjson::Reader reader;
    const rapidjson::ParseResult res = reader.Parse(ss, handler);
    if (res.IsError()) {
        // Not interested in partial JSON for now
        return owned_object::make_uninit(alloc);
    }

    return handler.finalize();
}

} // namespace ddwaf
