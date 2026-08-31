// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <optional>
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

// RapidJSON stream which appends one virtual closing quote without copying the input.
// It is used to decode a terminal string whose final bytes were cut off.
struct synthetic_closing_quote_stream {
    using Ch = std::string_view::value_type;

    explicit synthetic_closing_quote_stream(std::string_view str) : src(str) {}

    [[nodiscard]] char Peek() const
    {
        if (idx < src.size()) {
            return src[idx];
        }
        if (idx == src.size()) {
            return '"';
        }
        return '\0';
    }
    char Take()
    {
        if (idx < src.size()) {
            return src[idx++];
        }
        if (idx++ == src.size()) {
            return '"';
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
    object_reader_handler(nonnull_ptr<memory::memory_resource> alloc, json_parse_mode mode)
        : alloc_(alloc), mode_(mode)
    { stack_.reserve(max_depth + 1); }
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
            return beyond_max_depth();
        }

        return emplace(owned_object::make_map(alloc_));
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
            return beyond_max_depth();
        }

        return emplace(owned_object::make_array(alloc_));
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

    [[nodiscard]] bool expects_map_key() const
    { return !stack_.empty() && stack_.back().is_map() && key_.is_invalid(); }

private:
    // Values beyond the depth limit are silently dropped in strict mode. The
    // truncated-prefix parser must not return a silently incomplete tree, so
    // exceeding the limit fails the parse instead.
    bool beyond_max_depth()
    {
        if (mode_ == json_parse_mode::truncated_prefix) {
            return false;
        }

        ++depth_skip_count_;
        return true;
    }

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
                    if (stack_.size() > max_depth) [[unlikely]] {
                        if (mode_ == json_parse_mode::truncated_prefix) {
                            return false;
                        }
                        depth_skip_count_ = 1;
                    }
                }
            }
        } catch (...) {
            return false;
        }

        return true;
    }

    nonnull_ptr<memory::memory_resource> alloc_;
    json_parse_mode mode_;
    owned_object root_;
    std::vector<borrowed_object> stack_;

    owned_object key_;

    std::size_t depth_skip_count_{0};

    static constexpr std::size_t max_depth = 20;
};

namespace {

constexpr uint16_t high_surrogate_min = 0xD800;
constexpr uint16_t high_surrogate_max = 0xDBFF;
constexpr uint16_t low_surrogate_min = 0xDC00;
constexpr uint16_t low_surrogate_max = 0xDFFF;

[[nodiscard]] bool is_hex_digit(char c)
{ return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }

[[nodiscard]] bool is_high_surrogate(uint16_t value)
{ return value >= high_surrogate_min && value <= high_surrogate_max; }

// Range of values an incomplete \uXXXX escape can still take, given the hex
// digits already present (all of which must be valid hex digits).
[[nodiscard]] std::optional<std::pair<uint16_t, uint16_t>> incomplete_escape_range(
    std::string_view digits)
{
    if (digits.size() >= 4) {
        return std::nullopt;
    }

    uint16_t value = 0;
    for (const char c : digits) {
        if (!is_hex_digit(c)) {
            return std::nullopt;
        }
        value = static_cast<uint16_t>(value << 4U);
        if (c >= '0' && c <= '9') {
            value = static_cast<uint16_t>(value + static_cast<uint16_t>(c - '0'));
        } else if (c >= 'a' && c <= 'f') {
            value = static_cast<uint16_t>(value + static_cast<uint16_t>(c - 'a' + 10));
        } else {
            value = static_cast<uint16_t>(value + static_cast<uint16_t>(c - 'A' + 10));
        }
    }

    const unsigned remaining = 4 - static_cast<unsigned>(digits.size());
    const auto lowest = static_cast<uint16_t>(value << (4U * remaining));
    const auto span = static_cast<uint16_t>((1U << (4U * remaining)) - 1U);
    return std::pair{lowest, static_cast<uint16_t>(lowest + span)};
}

[[nodiscard]] std::optional<uint16_t> parse_hex_escape(std::string_view json, std::size_t offset)
{
    if (offset + 6 > json.size() || json[offset] != '\\' || json[offset + 1] != 'u') {
        return std::nullopt;
    }

    uint16_t value = 0;
    for (std::size_t idx = offset + 2; idx < offset + 6; ++idx) {
        const char c = json[idx];
        if (!is_hex_digit(c)) {
            return std::nullopt;
        }
        value = static_cast<uint16_t>(value << 4U);
        if (c >= '0' && c <= '9') {
            value = static_cast<uint16_t>(value + static_cast<uint16_t>(c - '0'));
        } else if (c >= 'a' && c <= 'f') {
            value = static_cast<uint16_t>(value + static_cast<uint16_t>(c - 'a' + 10));
        } else {
            value = static_cast<uint16_t>(value + static_cast<uint16_t>(c - 'A' + 10));
        }
    }
    return value;
}

// An incomplete \uXXXX escape at the end of the input is recoverable only when
// the digits already present can still be completed into a valid escape: an
// escape following a high surrogate must be able to land in the low-surrogate
// range, and a standalone escape must be able to avoid it (a lone low
// surrogate can never form a valid code point, while a high surrogate may
// still be completed by a later low surrogate).
[[nodiscard]] bool is_incomplete_unicode_escape(std::string_view json, std::size_t offset)
{
    if (offset + 2 > json.size() || json[offset] != '\\' || json[offset + 1] != 'u') {
        return false;
    }

    const auto range = incomplete_escape_range(json.substr(offset + 2));
    if (!range) {
        return false;
    }

    if (offset >= 6) {
        const auto previous = parse_hex_escape(json, offset - 6);
        if (previous && is_high_surrogate(*previous)) {
            return range->second >= low_surrogate_min && range->first <= low_surrogate_max;
        }
    }

    return !(range->first >= low_surrogate_min && range->second <= low_surrogate_max);
}

[[nodiscard]] bool is_incomplete_surrogate_pair(std::string_view json, std::size_t offset)
{
    const auto codepoint = parse_hex_escape(json, offset);
    if (!codepoint || *codepoint < 0xD800 || *codepoint > 0xDBFF) {
        return false;
    }

    const std::size_t low_surrogate_offset = offset + 6;
    if (low_surrogate_offset == json.size()) {
        return true;
    }
    if (json[low_surrogate_offset] != '\\') {
        return false;
    }
    if (low_surrogate_offset + 1 == json.size()) {
        return true;
    }
    if (json[low_surrogate_offset + 1] != 'u') {
        return false;
    }

    // The digits must still be able to complete into a low surrogate.
    const auto range = incomplete_escape_range(json.substr(low_surrogate_offset + 2));
    return range && range->second >= low_surrogate_min && range->first <= low_surrogate_max;
}

[[nodiscard]] bool is_incomplete_utf8_sequence(std::string_view json, std::size_t offset)
{
    if (offset >= json.size()) {
        return false;
    }

    const auto first = static_cast<uint8_t>(json[offset]);
    std::size_t expected = 0;
    if (first >= 0xC2 && first <= 0xDF) {
        expected = 2;
    } else if (first >= 0xE0 && first <= 0xEF) {
        expected = 3;
    } else if (first >= 0xF0 && first <= 0xF4) {
        expected = 4;
    } else {
        return false;
    }

    const std::size_t available = json.size() - offset;
    if (available >= expected) {
        return false;
    }

    if (available >= 2) {
        const auto second = static_cast<uint8_t>(json[offset + 1]);
        const bool valid_second =
            (first == 0xE0 && second >= 0xA0 && second <= 0xBF) ||
            (first == 0xED && second >= 0x80 && second <= 0x9F) ||
            (first == 0xF0 && second >= 0x90 && second <= 0xBF) ||
            (first == 0xF4 && second >= 0x80 && second <= 0x8F) ||
            (((first >= 0xC2 && first <= 0xDF) || (first >= 0xE1 && first <= 0xEC) ||
                 (first >= 0xEE && first <= 0xEF) || (first >= 0xF1 && first <= 0xF3)) &&
                second >= 0x80 && second <= 0xBF);
        if (!valid_second) {
            return false;
        }
    }

    for (std::size_t idx = offset + 2; idx < json.size(); ++idx) {
        const auto byte = static_cast<uint8_t>(json[idx]);
        if (byte < 0x80 || byte > 0xBF) {
            return false;
        }
    }
    return true;
}

enum class recovery_action : uint8_t { reject, finalize, recover_string };

// Recovery is allowed only when the reader consumed the whole prefix and the
// remaining token is structurally incomplete. Invalid bytes already present in
// the prefix must remain hard failures.
[[nodiscard]] recovery_action classify_end_of_input_error(
    std::string_view json, const rapidjson::ParseResult &result, std::size_t consumed)
{
    if (consumed != json.size()) {
        return recovery_action::reject;
    }

    const std::size_t error_offset = result.Offset();
    switch (result.Code()) {
    case rapidjson::kParseErrorValueInvalid:
    case rapidjson::kParseErrorObjectMissName:
    case rapidjson::kParseErrorObjectMissColon:
    case rapidjson::kParseErrorObjectMissCommaOrCurlyBracket:
    case rapidjson::kParseErrorArrayMissCommaOrSquareBracket:
    case rapidjson::kParseErrorNumberMissFraction:
    case rapidjson::kParseErrorNumberMissExponent:
        return recovery_action::finalize;
    case rapidjson::kParseErrorStringMissQuotationMark:
        return recovery_action::recover_string;
    case rapidjson::kParseErrorStringEscapeInvalid:
        return error_offset + 1 == json.size() && json[error_offset] == '\\'
                   ? recovery_action::recover_string
                   : recovery_action::reject;
    case rapidjson::kParseErrorStringUnicodeEscapeInvalidHex:
        return is_incomplete_unicode_escape(json, error_offset) ||
                       is_incomplete_surrogate_pair(json, error_offset)
                   ? recovery_action::recover_string
                   : recovery_action::reject;
    case rapidjson::kParseErrorStringUnicodeSurrogateInvalid:
        return is_incomplete_surrogate_pair(json, error_offset) ? recovery_action::recover_string
                                                                : recovery_action::reject;
    case rapidjson::kParseErrorStringInvalidEncoding:
        return is_incomplete_utf8_sequence(json, error_offset) ? recovery_action::recover_string
                                                               : recovery_action::reject;
    default:
        return recovery_action::reject;
    }
}

[[nodiscard]] std::optional<std::size_t> find_unclosed_string(std::string_view json)
{
    std::optional<std::size_t> start;
    bool escaped = false;
    for (std::size_t idx = 0; idx < json.size(); ++idx) {
        const char c = json[idx];
        if (!start) {
            if (c == '"') {
                start = idx;
            }
        } else if (escaped) {
            escaped = false;
        } else if (c == '\\') {
            escaped = true;
        } else if (c == '"') {
            start.reset();
        }
    }
    return start;
}

class recovered_string_handler
    : public rapidjson::BaseReaderHandler<rapidjson::UTF8<>, recovered_string_handler> {
public:
    explicit recovered_string_handler(object_reader_handler &target) : target_(&target) {}

    bool String(const char *str, rapidjson::SizeType length, bool copy)
    {
        recovered_ = target_->String(str, length, copy);
        return recovered_;
    }

    [[nodiscard]] bool recovered() const { return recovered_; }

private:
    object_reader_handler *target_;
    bool recovered_{false};
};

// Reparse the terminal string with a virtual closing quote. RapidJSON remains
// responsible for escape and UTF-8 decoding; bytes belonging to a partial escape,
// surrogate pair, or UTF-8 code point are excluded using the original error offset.
[[nodiscard]] bool recover_incomplete_string_value(
    std::string_view json, const rapidjson::ParseResult &result, object_reader_handler &handler)
{
    if (handler.expects_map_key()) {
        return true;
    }

    const auto string_start = find_unclosed_string(json);
    if (!string_start) {
        return false;
    }

    const std::size_t string_end = result.Code() == rapidjson::kParseErrorStringMissQuotationMark
                                       ? json.size()
                                       : result.Offset();
    if (string_end <= *string_start) {
        return false;
    }

    synthetic_closing_quote_stream stream(json.substr(*string_start, string_end - *string_start));
    recovered_string_handler recovered_handler(handler);
    rapidjson::Reader reader;
    constexpr unsigned flags = rapidjson::kParseValidateEncodingFlag;
    const rapidjson::ParseResult recovered_result = reader.Parse<flags>(stream, recovered_handler);
    return !recovered_result.IsError() && recovered_handler.recovered();
}

} // namespace

owned_object json_to_object(
    std::string_view json, nonnull_ptr<memory::memory_resource> alloc, json_parse_mode mode)
{
    object_reader_handler handler{alloc, mode};
    string_view_stream ss(json);

    rapidjson::Reader reader;
    // An iterative reader avoids growing the native call stack when the input ends
    // with several open containers. The handler already owns every completed value,
    // so successful recovery only needs to finalize that partial tree.
    constexpr unsigned prefix_parse_flags =
        rapidjson::kParseIterativeFlag | rapidjson::kParseValidateEncodingFlag;
    const rapidjson::ParseResult res = mode == json_parse_mode::strict
                                           ? reader.Parse(ss, handler)
                                           : reader.Parse<prefix_parse_flags>(ss, handler);
    if (res.IsError()) {
        if (mode == json_parse_mode::strict) {
            return owned_object{};
        }

        const recovery_action action = classify_end_of_input_error(json, res, ss.Tell());
        if (action == recovery_action::reject ||
            (action == recovery_action::recover_string &&
                !recover_incomplete_string_value(json, res, handler))) {
            return owned_object{};
        }
    } else if (ss.Tell() != json.size()) {
        // The stream reports end-of-input as '\0', which is indistinguishable
        // from an embedded NUL byte. A successful parse must therefore have
        // consumed the entire input to reject trailing content such as a NUL
        // followed by arbitrary bytes.
        return owned_object{};
    }

    return handler.finalize();
}

} // namespace ddwaf
