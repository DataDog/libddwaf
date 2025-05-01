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
#include <vector>

#include "ddwaf.h"
#include "json_utils.hpp"
#include "utils.hpp"

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
    object_reader_handler() { stack_.reserve(max_depth + 1); }
    ~object_reader_handler()
    {
        // Cleanup
        ddwaf_object_free(&root_);
        if (key_ != nullptr) {
            // NOLINTNEXTLINE(hicpp-no-malloc)
            free(key_);
        }
    }
    bool Null()
    {
        if (stack_.size() > max_depth) [[unlikely]] {
            return true;
        }

        ddwaf_object object;
        return emplace(ddwaf_object_null(&object));
    }

    bool Bool(bool b)
    {
        if (stack_.size() > max_depth) [[unlikely]] {
            return true;
        }

        ddwaf_object object;
        return emplace(ddwaf_object_bool(&object, b));
    }

    bool Int(int i)
    {
        if (stack_.size() > max_depth) [[unlikely]] {
            return true;
        }

        ddwaf_object object;
        return emplace(ddwaf_object_signed(&object, i));
    }

    bool Uint(unsigned u)
    {
        if (stack_.size() > max_depth) [[unlikely]] {
            return true;
        }

        ddwaf_object object;
        return emplace(ddwaf_object_unsigned(&object, u));
    }

    bool Int64(int64_t i)
    {
        if (stack_.size() > max_depth) [[unlikely]] {
            return true;
        }

        ddwaf_object object;
        return emplace(ddwaf_object_signed(&object, i));
    }

    bool Uint64(uint64_t u)
    {
        if (stack_.size() > max_depth) [[unlikely]] {
            return true;
        }

        ddwaf_object object;
        return emplace(ddwaf_object_unsigned(&object, u));
    }

    bool Double(double d)
    {
        if (stack_.size() > max_depth) [[unlikely]] {
            return true;
        }

        ddwaf_object object;
        return emplace(ddwaf_object_float(&object, d));
    }

    bool String(const char *str, rapidjson::SizeType length, bool /*copy*/)
    {
        if (stack_.size() > max_depth) [[unlikely]] {
            return true;
        }

        ddwaf_object object;
        return emplace(ddwaf_object_stringl(&object, str, length));
    }

    bool Key(const char *str, rapidjson::SizeType length, bool /*copy*/)
    {
        if (stack_.size() > max_depth) [[unlikely]] {
            return true;
        }

        // NOLINTNEXTLINE(hicpp-no-malloc)
        key_ = static_cast<char *>(malloc(length));
        if (key_ == nullptr) {
            return false;
        }

        memcpy(key_, str, length);
        key_size_ = length;

        return true;
    }

    bool StartObject()
    {
        if (stack_.size() > max_depth) [[unlikely]] {
            ++depth_skip_count_;
            return true;
        }

        ddwaf_object object;
        return emplace(ddwaf_object_map(&object));
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

        ddwaf_object object;
        return emplace(ddwaf_object_array(&object));
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

    ddwaf_object finalize()
    {
        auto final_object = root_;
        root_ = {};
        stack_.clear();
        return final_object;
    }

private:
    bool emplace(ddwaf_object *object)
    {

        bool res = true;
        const bool is_container = (object->type & (DDWAF_OBJ_MAP | DDWAF_OBJ_ARRAY)) != 0;

        if (stack_.empty()) {
            assert(root_.type == DDWAF_OBJ_INVALID);
            root_ = *object;
            if (is_container) {
                stack_.push_back(&root_);
                // No need to check for the stack limit here
            }
        } else {
            auto *container = stack_.back();
            if (container->type == DDWAF_OBJ_MAP) {
                res = ddwaf_object_map_addl_nc(container, key_, key_size_, object);

                // Reset key
                key_ = nullptr;
                key_size_ = 0;
            } else if (container->type == DDWAF_OBJ_ARRAY) {
                res = ddwaf_object_array_add(container, object);
            } else {
                // Shouldn't happen
                ddwaf_object_free(object);
                res = false;
            }

            if (res && is_container) {
                stack_.push_back(&container->array[container->nbEntries - 1]);
                if (stack_.size() > max_depth) {
                    depth_skip_count_ = 1;
                }
            }
        }

        return res;
    }

    ddwaf_object root_{};
    std::vector<ddwaf_object *> stack_;

    char *key_{nullptr};
    std::size_t key_size_{0};

    std::size_t depth_skip_count_{0};

    static constexpr std::size_t max_depth = object_limits::default_max_container_depth;
};

ddwaf_object json_to_object(std::string_view json)
{
    object_reader_handler handler;
    string_view_stream ss(json);

    rapidjson::Reader reader;
    const rapidjson::ParseResult res = reader.Parse(ss, handler);
    if (res.IsError()) {
        // Not interested in partial JSON for now
        return {};
    }

    return handler.finalize();
}

} // namespace ddwaf
