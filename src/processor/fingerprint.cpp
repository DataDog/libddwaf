// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <new>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "argument_retriever.hpp"
#include "clock.hpp"
#include "exception.hpp"
#include "log.hpp"
#include "object.hpp"
#include "object_store.hpp"
#include "object_type.hpp"
#include "object_view.hpp"
#include "processor/base.hpp"
#include "processor/fingerprint.hpp"
#include "sha256.hpp"
#include "transformer/common/cow_string.hpp"
#include "transformer/lowercase.hpp"
#include "utils.hpp"

namespace ddwaf {
namespace {

struct string_buffer {
    explicit string_buffer(std::size_t length)
        // NOLINTNEXTLINE(hicpp-no-malloc,cppcoreguidelines-pro-type-reinterpret-cast)
        : buffer(reinterpret_cast<char *>(malloc(sizeof(char) * (length + 1)))), length(length)
    {
        if (buffer == nullptr) {
            throw std::bad_alloc{};
        }
    }

    // NOLINTNEXTLINE(hicpp-no-malloc,cppcoreguidelines-pro-type-reinterpret-cast)
    ~string_buffer() { free(buffer); }

    string_buffer(const string_buffer &) = delete;
    string_buffer(string_buffer &&) = delete;

    string_buffer &operator=(const string_buffer &) = delete;
    string_buffer &operator=(string_buffer &&) = delete;

    void append(std::string_view str)
    {
        if (!str.empty() && (index + str.size()) <= length) [[likely]] {
            memcpy(&buffer[index], str.data(), str.size());
            index += str.size();
        }
    }

    void append(char c)
    {
        if (index < length) [[likely]] {
            buffer[index++] = c;
        }
    }

    owned_object to_object()
    {
        buffer[index] = '\0';

        auto object = owned_object::make_string_nocopy(buffer, index);
        buffer = nullptr;
        return object; // NOLINT(clang-analyzer-unix.Malloc)
    }

    char *buffer{nullptr};
    std::size_t index{0};
    std::size_t length;
};

// Return true if the first argument is less than (i.e. is ordered before) the second
bool str_casei_cmp(std::string_view left, std::string_view right)
{
    auto n = std::min(left.size(), right.size());
    for (std::size_t i = 0; i < n; ++i) {
        auto lc = ddwaf::tolower(left[i]);
        auto rc = ddwaf::tolower(right[i]);
        if (lc != rc) {
            return lc < rc;
        }
    }
    return left.size() < right.size();
}

// Default key normalization implies:
// - Lowercasing the string
// - Escaping commas
// - Adding trailing commas
void normalize_key(std::string_view key, std::string &buffer, bool trailing_separator)
{
    buffer.clear();

    if (buffer.capacity() < key.size()) {
        // Add space for the extra comma, just in case
        buffer.reserve(key.size() + 1);
    }

    for (auto c : key) {
        if (c == ',') {
            buffer.append(R"(\,)");
        } else {
            buffer.append(1, ddwaf::tolower(c));
        }
    }

    if (trailing_separator) {
        buffer.append(1, ',');
    }
}

// Header normalization implies:
// - Lowercasing the header
// - Replacing '_' with '-'
void normalize_header(std::string_view original, std::string &buffer)
{
    buffer.resize(original.size());

    for (std::size_t i = 0; i < original.size(); ++i) {
        const auto c = original[i];
        buffer[i] = c == '_' ? '-' : ddwaf::tolower(c);
    }
}

// Value (as opposed to key) normalisation only requires escaping commas
void normalize_value(std::string_view key, std::string &buffer, bool trailing_separator)
{
    buffer.clear();

    if (buffer.capacity() < key.size()) {
        // Add space for the extra comma, just in case
        buffer.reserve(key.size() + 1);
    }

    for (std::size_t i = 0; i < key.size(); ++i) {
        auto comma_idx = key.find(',', i);
        if (comma_idx != std::string_view::npos) {
            if (comma_idx != i) {
                buffer.append(key.substr(i, comma_idx - i));
            }
            buffer.append(R"(\,)");
            i = comma_idx;
        } else {
            buffer.append(key.substr(i));
            break;
        }
    }

    if (trailing_separator) {
        buffer.append(1, ',');
    }
}

template <typename Derived, typename Output = std::string> struct field_generator {
    using output_type = Output;

public:
    ~field_generator() = default;
    field_generator &operator=(const field_generator &) = default;
    field_generator &operator=(field_generator &&) noexcept = default;

    [[nodiscard]] static constexpr bool has_value() { return true; }
    [[nodiscard]] static constexpr std::size_t fields()
    {
        if constexpr (is_pair_v<output_type>) {
            return 2;
        } else {
            return 1;
        }
    }
    output_type operator()() { return static_cast<Derived *>(this)->generate(); }

private:
    field_generator(const field_generator &) = default;
    field_generator() = default;
    field_generator(field_generator &&) noexcept = default;
    friend Derived;
};

struct string_field : field_generator<string_field> {
    explicit string_field(std::string_view input) : value(input) {}
    // NOLINTNEXTLINE(readability-make-member-function-const)
    [[nodiscard]] std::string generate()
    {
        auto buffer = std::string{value};

        auto str_lc = cow_string::from_mutable_buffer(buffer.data(), buffer.size());
        transformer::lowercase::transform(str_lc);

        return buffer; // NOLINT(clang-analyzer-unix.Malloc)
    }

    std::string_view value;
};

template <typename T>
    requires std::is_unsigned_v<T>
struct unsigned_field : field_generator<unsigned_field<T>> {
    explicit unsigned_field(T input) : value(input) {}

    [[nodiscard]] std::string generate() { return ddwaf::to_string<std::string>(value); }

    T value;
};

struct string_hash_field : field_generator<string_hash_field> {
    explicit string_hash_field(std::string_view input) : value(input) {}

    // NOLINTNEXTLINE(readability-make-member-function-const)
    [[nodiscard]] std::string generate()
    {
        if (value.empty()) {
            return {};
        }

        cow_string value_lc{value};
        transformer::lowercase::transform(value_lc);

        sha256_hash hasher;
        hasher << static_cast<std::string_view>(value_lc);

        return hasher.digest<8>();
    }

    std::string_view value;
};

struct key_hash_field : field_generator<key_hash_field> {
    explicit key_hash_field(object_view input) : value(input) {}

    // NOLINTNEXTLINE(readability-make-member-function-const)
    [[nodiscard]] std::string generate()
    {
        if (!value.has_value() || value.type() != object_type::map || value.empty()) {
            return {};
        }

        std::vector<std::string_view> keys;
        keys.reserve(value.size());

        std::size_t max_string_size = 0;
        for (auto it = value.begin(); it != value.end(); ++it) {
            const auto key = it.key();
            max_string_size = std::max(max_string_size, key.size());

            keys.emplace_back(key.as<std::string_view>());
        }

        std::sort(keys.begin(), keys.end(), str_casei_cmp);

        std::string normalized;
        // By reserving the largest possible size, it should reduce reallocations
        // We also add +1 to account for the trailing comma
        normalized.reserve(max_string_size + 1);

        sha256_hash hasher;
        for (unsigned i = 0; i < keys.size(); ++i) {
            const bool trailing_comma = ((i + 1) < keys.size());
            normalize_key(keys[i], normalized, trailing_comma);
            hasher << normalized;
        }
        return hasher.digest<8>();
    }

    object_view value;
};

struct vector_hash_field : field_generator<vector_hash_field> {
    explicit vector_hash_field(std::vector<std::string> &&input) : value(std::move(input)) {}

    // NOLINTNEXTLINE(readability-make-member-function-const)
    [[nodiscard]] std::string generate()
    {
        if (value.empty()) {
            return {};
        }

        sha256_hash hasher;
        for (unsigned i = 0; i < value.size(); ++i) {
            hasher << value[i];
            if ((i + 1) < value.size()) {
                hasher << ",";
            }
        }
        return hasher.digest<8>();
    }

    std::vector<std::string> value;
};

// This particular generator generates multiple fields (hence the fields name)
// This is to prevent having to create intermediate structures for key and value
// when both have to be processed together. This generator also includes the
// relevant separator, whether the map is empty or not.
struct kv_hash_fields : field_generator<kv_hash_fields, std::pair<std::string, std::string>> {
    explicit kv_hash_fields(object_view input) : value(input) {}

    // NOLINTNEXTLINE(readability-make-member-function-const)
    [[nodiscard]] std::pair<std::string, std::string> generate()
    {
        if (!value.has_value() || value.type() != object_type::map || value.empty()) {
            return {};
        }

        std::vector<std::pair<std::string_view, std::string_view>> kv_sorted;
        kv_sorted.reserve(value.size());

        std::size_t max_string_size = 0;
        for (auto it = value.begin(); it != value.end(); ++it) {
            const auto key = it.key();
            const auto child = it.value();

            auto val = child.as_or_default<std::string_view>({});

            auto larger_size = std::max(key.size(), val.size());
            max_string_size = std::max(max_string_size, larger_size);

            kv_sorted.emplace_back(key.as<std::string_view>(), val);
        }

        std::sort(kv_sorted.begin(), kv_sorted.end(),
            [](auto &left, auto &right) { return str_casei_cmp(left.first, right.first); });

        std::string normalized;
        // By reserving the largest possible size, it should reduce reallocations
        // We also add +1 to account for the trailing comma
        normalized.reserve(max_string_size + 1);
        sha256_hash key_hasher;
        sha256_hash val_hasher;
        for (unsigned i = 0; i < kv_sorted.size(); ++i) {
            auto [key, val] = kv_sorted[i];

            const bool trailing_comma = ((i + 1) < kv_sorted.size());

            normalize_key(key, normalized, trailing_comma);
            key_hasher << normalized;

            normalize_value(val, normalized, trailing_comma);
            val_hasher << normalized;
        }

        return {key_hasher.digest<8>(), val_hasher.digest<8>()};
    }

    object_view value;
};

template <typename Generator> struct optional_generator {
    using output_type = typename Generator::output_type;

    template <typename T> explicit optional_generator(const optional_argument<T> &input)
    {
        if (input.has_value()) {
            generator = Generator{input.value().value};
        }
    }
    ~optional_generator() = default;
    optional_generator(const optional_generator &) = default;
    optional_generator(optional_generator &&) noexcept = default;
    optional_generator &operator=(const optional_generator &) = default;
    optional_generator &operator=(optional_generator &&) noexcept = default;

    [[nodiscard]] bool has_value() const { return generator.has_value(); }
    [[nodiscard]] static constexpr std::size_t fields() { return Generator::fields(); }
    output_type operator()()
    {
        if (generator.has_value()) {
            return (*generator)();
        }
        return {};
    }

    std::optional<Generator> generator;
};

template <typename... Generators> std::size_t generate_fragment_length(Generators &...generators)
{
    static_assert(sizeof...(generators) > 0, "At least one generator is required");
    return ((generators.length() * generators.fields()) + ...) + (generators.fields() + ...);
}

template <typename... Generators> constexpr std::size_t generate_num_fields()
{
    static_assert(sizeof...(Generators) > 0, "At least one generator is required");
    return (Generators::fields() + ...);
}

template <std::size_t N, typename T, typename... Rest>
std::size_t generate_fragment_field(std::span<std::string, N> fields, T &generator, Rest &&...rest)
{
    std::size_t length = 0;
    auto value = generator();
    if constexpr (is_pair_v<typename T::output_type> && N >= 2) {
        length += value.first.size() + value.second.size();
        fields[0] = std::move(value.first);
        fields[1] = std::move(value.second);
    } else {
        length += value.size();
        fields[0] = std::move(value);
    }

    if constexpr (sizeof...(rest) > 0) {
        if constexpr (is_pair_v<typename T::output_type>) {
            return length + generate_fragment_field(fields.subspan(2), std::forward<Rest>(rest)...);
        } else {
            return length + generate_fragment_field(fields.subspan(1), std::forward<Rest>(rest)...);
        }
    } else {
        return length;
    }
}

template <typename... Generators>
owned_object generate_fragment(std::string_view header, Generators... generators)
{
    constexpr std::size_t num_fields = generate_num_fields<Generators...>();
    std::array<std::string, num_fields> fields;

    auto length =
        generate_fragment_field(std::span<std::string, num_fields>{fields}, generators...);

    string_buffer buffer{length + header.size() + num_fields};
    buffer.append(header);
    for (const auto &field : fields) {
        buffer.append('-');
        buffer.append(field);
    }

    // NOLINTNEXTLINE(clang-analyzer-unix.Malloc)
    return buffer.to_object();
}

template <typename T, typename... Rest>
std::size_t generate_fragment_field_cached(
    std::span<std::optional<std::string>> cache, T &generator, Rest &&...rest)
{
    std::size_t length = 0;
    if constexpr (is_pair_v<typename T::output_type>) {
        // We can assume that cache[1] will have a value as well
        if (cache[0].has_value() && cache[1].has_value()) {
            length += cache[0]->size() + cache[1]->size();
        } else if (generator.has_value()) {
            auto value = generator();
            cache[0] = value.first;
            cache[1] = value.second;
            length += cache[0]->size() + cache[1]->size();
        }
    } else {
        if (cache[0].has_value()) {
            length += cache[0]->size();
        } else if (generator.has_value()) {
            cache[0] = generator();
            length += cache[0]->size();
        }
    }

    if constexpr (sizeof...(rest) > 0) {
        if constexpr (is_pair_v<typename T::output_type>) {
            return length +
                   generate_fragment_field_cached(cache.subspan(2), std::forward<Rest>(rest)...);
        } else {
            return length +
                   generate_fragment_field_cached(cache.subspan(1), std::forward<Rest>(rest)...);
        }
    } else {
        return length;
    }
}

template <typename... Generators>
owned_object generate_fragment_cached(std::string_view header,
    std::vector<std::optional<std::string>> &cache, Generators... generators)
{
    constexpr std::size_t num_fields = generate_num_fields<Generators...>();
    if (cache.empty()) {
        cache.resize(num_fields);
    }

    auto length = generate_fragment_field_cached(cache, generators...);

    string_buffer buffer{length + header.size() + num_fields};
    buffer.append(header);
    for (const auto &field : cache) {
        buffer.append('-');
        if (field.has_value()) {
            buffer.append(*field);
        }
    }

    // NOLINTNEXTLINE(clang-analyzer-unix.Malloc)
    return buffer.to_object();
}

enum class header_type : uint8_t { unknown, standard, ip_origin, user_agent, datadog };

constexpr std::size_t standard_headers_length = 10;
constexpr std::size_t ip_origin_headers_length = 10;

std::pair<header_type, unsigned> get_header_type_and_index(std::string_view header)
{
    static std::unordered_map<std::string_view, std::pair<header_type, unsigned>> headers{
        {"referer", {header_type::standard, 0}}, {"connection", {header_type::standard, 1}},
        {"accept-encoding", {header_type::standard, 2}},
        {"content-encoding", {header_type::standard, 3}},
        {"cache-control", {header_type::standard, 4}}, {"te", {header_type::standard, 5}},
        {"accept-charset", {header_type::standard, 6}},
        {"content-type", {header_type::standard, 7}}, {"accept", {header_type::standard, 8}},
        {"accept-language", {header_type::standard, 9}},
        {"x-forwarded-for", {header_type::ip_origin, 0}},
        {"x-real-ip", {header_type::ip_origin, 1}}, {"true-client-ip", {header_type::ip_origin, 2}},
        {"x-client-ip", {header_type::ip_origin, 3}}, {"x-forwarded", {header_type::ip_origin, 4}},
        {"forwarded-for", {header_type::ip_origin, 5}},
        {"x-cluster-client-ip", {header_type::ip_origin, 6}},
        {"fastly-client-ip", {header_type::ip_origin, 7}},
        {"cf-connecting-ip", {header_type::ip_origin, 8}},
        {"cf-connecting-ipv6", {header_type::ip_origin, 9}},
        {"user-agent", {header_type::user_agent, 0}}};

    if (header.starts_with("x-datadog")) {
        return {header_type::datadog, 0};
    }

    auto it = headers.find(header);
    if (it == headers.end()) {
        return {header_type::unknown, 0};
    }
    return it->second;
}

} // namespace

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
std::pair<owned_object, object_store::attribute> http_endpoint_fingerprint::eval_impl(
    const unary_argument<std::string_view> &method, const unary_argument<std::string_view> &uri_raw,
    const optional_argument<object_view> &query, const optional_argument<object_view> &body,
    processor_cache &cache, ddwaf::timer &deadline) const
{
    if (deadline.expired()) {
        throw ddwaf::timeout_exception();
    }

    // Strip query parameter from raw URI
    auto stripped_uri = uri_raw.value;
    auto query_or_frag_idx = stripped_uri.find_first_of("?#");
    if (query_or_frag_idx != std::string_view::npos) {
        stripped_uri = stripped_uri.substr(0, query_or_frag_idx);
    }

    owned_object res;
    try {
        res = generate_fragment_cached("http", cache.fingerprint.fragment_fields,
            string_field{method.value}, string_hash_field{stripped_uri},
            optional_generator<key_hash_field>{query}, optional_generator<key_hash_field>{body});
    } catch (const std::out_of_range &e) {
        DDWAF_WARN("Failed to generate http endpoint fingerprint: {}", e.what());
    }

    return {std::move(res), object_store::attribute::none};
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
std::pair<owned_object, object_store::attribute> http_header_fingerprint::eval_impl(
    const unary_argument<object_view> &headers, processor_cache & /*cache*/,
    ddwaf::timer &deadline) const
{
    if (headers.value.type() != object_type::map) {
        return {owned_object{}, object_store::attribute::none};
    }

    std::string known_header_bitset;
    known_header_bitset.resize(standard_headers_length, '0');

    std::string_view user_agent;
    std::vector<std::string> unknown_headers;
    std::string normalized_header;
    for (auto it = headers.value.begin(); it != headers.value.end(); ++it) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        const auto header = it.key().as<std::string_view>();
        const auto child = it.value();

        normalize_header(header, normalized_header);
        auto [type, index] = get_header_type_and_index(normalized_header);
        if (type == header_type::standard) {
            known_header_bitset[index] = '1';
        } else if (type == header_type::unknown) {
            unknown_headers.emplace_back(normalized_header);
        } else if (type == header_type::user_agent && child.is<std::string_view>()) {
            user_agent = child.as<std::string_view>();
        }
    }
    std::sort(unknown_headers.begin(), unknown_headers.end());

    auto unknown_header_size = unknown_headers.size();
    owned_object res;
    try {
        res = generate_fragment("hdr", string_field{known_header_bitset},
            string_hash_field{user_agent}, unsigned_field{unknown_header_size},
            vector_hash_field{std::move(unknown_headers)});
    } catch (const std::out_of_range &e) {
        DDWAF_WARN("Failed to generate http header fingerprint: {}", e.what());
    }

    return {std::move(res), object_store::attribute::none};
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
std::pair<owned_object, object_store::attribute> http_network_fingerprint::eval_impl(
    const unary_argument<object_view> &headers, processor_cache & /*cache*/,
    ddwaf::timer &deadline) const
{
    if (headers.value.type() != object_type::map) {
        return {owned_object{}, object_store::attribute::none};
    }

    std::string ip_origin_bitset;
    ip_origin_bitset.resize(ip_origin_headers_length, '0');

    unsigned chosen_header = ip_origin_headers_length;
    std::string_view chosen_header_value;
    std::string normalized_header;
    for (auto it = headers.value.begin(); it != headers.value.end(); ++it) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        const auto header = it.key().as<std::string_view>();
        const auto &child = it.value();

        normalize_header(header, normalized_header);
        auto [type, index] = get_header_type_and_index(normalized_header);
        if (type == header_type::ip_origin) {
            ip_origin_bitset[index] = '1';
            // Verify not only precedence but also type, as a header of an unexpected
            // type will be unlikely to be used unless the framework has somehow
            // broken down the header into constituent IPs
            if (chosen_header > index && child.is<std::string_view>()) {
                chosen_header_value = child.as<std::string_view>();
                chosen_header = index;
            }
        }
    }

    unsigned ip_count = 0;
    if (!chosen_header_value.empty()) {
        // For now, count commas
        ++ip_count;
        for (auto c : chosen_header_value) { ip_count += static_cast<unsigned int>(c == ','); }
    }

    owned_object res;
    try {
        res = generate_fragment("net", unsigned_field{ip_count}, string_field{ip_origin_bitset});
    } catch (const std::out_of_range &e) {
        DDWAF_WARN("Failed to generate http network fingerprint: {}", e.what());
    }

    return {std::move(res), object_store::attribute::none};
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
std::pair<owned_object, object_store::attribute> session_fingerprint::eval_impl(
    const optional_argument<object_view> &cookies,
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    const optional_argument<std::string_view> &session_id,
    const optional_argument<std::string_view> &user_id, processor_cache &cache,
    ddwaf::timer &deadline) const
{
    if (deadline.expired()) {
        throw ddwaf::timeout_exception();
    }

    owned_object res;
    try {
        res = generate_fragment_cached("ssn", cache.fingerprint.fragment_fields,
            optional_generator<string_hash_field>{user_id},
            optional_generator<kv_hash_fields>{cookies},
            optional_generator<string_hash_field>{session_id});
    } catch (const std::out_of_range &e) {
        DDWAF_WARN("Failed to generate session fingerprint: {}", e.what());
    }

    return {std::move(res), object_store::attribute::none};
}

} // namespace ddwaf
