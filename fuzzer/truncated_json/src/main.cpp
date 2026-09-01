// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026 Datadog, Inc.

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "json_utils.hpp"
#include "memory_resource.hpp"

namespace {

bool parses_truncated(std::string_view json)
{
    return !ddwaf::json_to_object(
        json, ddwaf::memory::get_default_resource(), ddwaf::json_parse_mode::truncated_prefix)
                .is_invalid();
}

bool parses_strict(std::string_view json)
{
    return !ddwaf::json_to_object(
        json, ddwaf::memory::get_default_resource(), ddwaf::json_parse_mode::strict)
                .is_invalid();
}

bool has_root_value(std::string_view json)
{
    // A bare root number cut mid-value (e.g. "1.") is not recoverable, so the
    // prefix-closure property only holds for container and string roots.
    static constexpr std::string_view whitespace = " \t\r\n";
    const auto pos = json.find_first_not_of(whitespace);
    return pos != std::string_view::npos && json[pos] != '-' &&
           (json[pos] < '0' || json[pos] > '9');
}

bool is_ascii(std::string_view json)
{
    // The strict parser does not validate the UTF-8 encoding of the input,
    // while the truncated-prefix parser does (this is what blocks truncated
    // multibyte sequences such as "\xed" from recovering into overlong or
    // surrogate code points). The strict-to-truncated implication below is
    // therefore only asserted for pure-ASCII inputs.
    for (const char c : json) {
        if (static_cast<unsigned char>(c) >= 0x80) {
            return false;
        }
    }
    return true;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *bytes, size_t size)
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const std::string_view json{reinterpret_cast<const char *>(bytes), size};

    const bool valid = parses_truncated(json);

    // Any document accepted by the strict parser is a complete, valid JSON
    // document and must also be accepted by the truncated-prefix parser.
    // This only holds for pure-ASCII input (see is_ascii): documents with
    // invalid UTF-8 are accepted by the strict parser but rejected by the
    // truncated-prefix parser, which validates the encoding.
    if (is_ascii(json) && parses_strict(json)) {
        assert(valid);
    }

    // The input stream treats '\0' as end-of-input, so an input containing a
    // NUL byte can never be part of a successfully parsed document.
    if (json.find('\0') != std::string_view::npos) {
        assert(!valid);
        return 0;
    }

    // Every prefix of a recoverable prefix must itself be recoverable, as
    // long as the prefix has already reached its root value: whitespace-only
    // prefixes and bare root numbers cut mid-value are not recoverable. The
    // check is O(n^2) so it is limited to small inputs, and it only applies
    // to container and string roots (see has_root_value).
    if (!valid || json.size() > 64 || !has_root_value(json)) {
        return 0;
    }

    for (std::size_t length = 1; length <= json.size(); ++length) {
        const auto prefix = json.substr(0, length);
        if (has_root_value(prefix)) {
            assert(parses_truncated(prefix));
        }
    }

    return 0;
}
