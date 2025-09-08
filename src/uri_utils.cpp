// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <optional>
#include <string_view>

#include "ip_utils.hpp"
#include "uri_utils.hpp"
#include "utils.hpp"

/*
   RFC 3986
   --
   URI           = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
   hier-part     = "//" authority path-abempty
                 / path-absolute
                 / path-rootless
                 / path-empty
   relative-ref  = relative-part [ "?" query ] [ "#" fragment ]
   relative-part = "//" authority path-abempty
                 / path-absolute
                 / path-noscheme -> Not supported
                 / path-empty -> Not supported
   scheme        = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
   authority     = [ userinfo "@" ] host [ ":" port ]
   userinfo      = *( unreserved / pct-encoded / sub-delims / ":" )
   host          = IP-literal / IPv4address / reg-name
   port          = *DIGIT
   IP-literal    = "[" IPv6address "]"
   IPv6address   =                            6( h16 ":" ) ls32
                 /                       "::" 5( h16 ":" ) ls32
                 / [               h16 ] "::" 4( h16 ":" ) ls32
                 / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
                 / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
                 / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
                 / [ *4( h16 ":" ) h16 ] "::"              ls32
                 / [ *5( h16 ":" ) h16 ] "::"              h16
                 / [ *6( h16 ":" ) h16 ] "::"
   h16           = 1*4HEXDIG
   ls32          = ( h16 ":" h16 ) / IPv4address
   IPv4address   = dec-octet "." dec-octet "." dec-octet "." dec-octet
   dec-octet     = DIGIT                 ; 0-9
                 / %x31-39 DIGIT         ; 10-99
                 / "1" 2DIGIT            ; 100-199
                 / "2" %x30-34 DIGIT     ; 200-249
                 / "25" %x30-35          ; 250-255
   reg-name      = *( unreserved / pct-encoded / sub-delims )
   path-abempty  = *( "/" segment )
   path-absolute = "/" [ segment-nz *( "/" segment ) ]
   path-rootless = segment-nz *( "/" segment )
   path-empty    = 0<pchar>
   segment       = *pchar
   segment-nz    = 1*pchar
   pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
   query         = *( ext-query-set / pchar / "/" / "?" )
   fragment      = *( pchar / "/" / "?" )
   pct-encoded   = "%" HEXDIG HEXDIG
   unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
   sub-delims    = "!" / "$" / "&" / "'" / "(" / ")"
                 / "*" / "+" / "," / ";" / "="
   ext-query-set = "[" / "]"

--
  To account for the extended use of [] characters in the query string, which
  is somewhat allowed by section 2.2 of RFC 3986, the ext-query-set has been
  introduced, but only to the query string.

  Note that these are also tolerated by the WHATWG standard.

  Discussion in https://stackoverflow.com/questions/11490326
*/

namespace ddwaf {

namespace {
enum class token_type : uint8_t {
    none,
    scheme,
    scheme_authority_or_path,
    hierarchical_part,
    authority,
    userinfo,
    host,
    port,
    ipv6address,
    regname_or_ipv4address,
    path,
    query,
    fragment,
};
constexpr const auto &npos = std::string_view::npos;

inline bool is_extended_query_set(char c) { return c == '[' || c == ']'; }

inline bool is_unreserved(char c)
{
    return ddwaf::isalnum(c) || c == '-' || c == '.' || c == '_' || c == '~';
}

inline bool is_subdelim(char c)
{
    return c == '!' || c == '$' || c == '&' || c == '\'' || c == '(' || c == ')' || c == '*' ||
           c == '+' || c == ',' || c == ';' || c == '=';
}

inline bool is_scheme_char(char c) { return ddwaf::isalnum(c) || c == '.' || c == '-' || c == '+'; }
inline bool is_host_char(char c) { return is_unreserved(c) || is_subdelim(c) || c == '%'; }
inline bool is_path_char(char c)
{
    return is_unreserved(c) || is_subdelim(c) || c == '%' || c == ':' || c == '@';
}
inline bool is_query_char(char c)
{
    return is_extended_query_set(c) || is_path_char(c) || c == '/' || c == '?';
}
inline bool is_frag_char(char c) { return is_path_char(c) || c == '/' || c == '?'; }

inline bool is_userinfo_char(char c)
{
    return is_unreserved(c) || is_subdelim(c) || c == ':' || c == '%';
}

inline bool is_regname_char(char c) { return is_unreserved(c) || is_subdelim(c) || c == '%'; }

} // namespace

std::optional<uri_decomposed> uri_parse(std::string_view uri)
{
    uri_decomposed decomposed;
    decomposed.raw = uri;

    auto expected_token = token_type::scheme_authority_or_path;
    auto lookahead_token = token_type::none;

    // Authority helpers
    std::size_t authority_end = npos;
    std::string_view authority_substr;

    for (std::size_t i = 0; i < uri.size();) {
        // Dead man's switch
        auto current_token = expected_token;
        expected_token = token_type::none;

        switch (current_token) {
        case token_type::scheme_authority_or_path: {
            if (uri[i] == '/') {
                // Path or authority
                if ((i + 1) < uri.size() && uri[i + 1] == '/') {
                    expected_token = token_type::authority;
                    i += 2;
                } else {
                    expected_token = token_type::path;
                }
            } else if (isalpha(uri[i])) {
                expected_token = token_type::scheme;
            }
            break;
        }
        case token_type::scheme: {
            auto token_begin = i;
            if (!isalpha(uri[i++])) {
                // The URI is malformed as the first character must be alphabetic
                return std::nullopt;
            }

            bool end_found = false;
            while (i < uri.size()) {
                const auto c = uri[i++];
                if (c == ':') {
                    // We reached the end of the scheme, move to the next token
                    end_found = true;
                    break;
                }

                if (!is_scheme_char(c)) {
                    return std::nullopt;
                }
            }

            if (!end_found) {
                return std::nullopt;
            }

            expected_token = token_type::hierarchical_part;
            decomposed.scheme = uri.substr(token_begin, i - 1);

            break;
        }
        case token_type::hierarchical_part: {
            if ((i + 1) < uri.size() && uri[i] == '/' && uri[i + 1] == '/') {
                // The authority always starts with //
                expected_token = token_type::authority;
                i += 2;
            } else {
                // Otherwise we expect a path (path-absolute, path-rootless, path-empty)
                expected_token = token_type::path;
            }
            break;
        }
        case token_type::authority: {
            auto token_begin = i;
            authority_end = uri.find_first_of("/?#", i);
            if (authority_end != npos) {
                const auto c = uri[authority_end];
                if (c == '/') {
                    lookahead_token = token_type::path;
                } else if (c == '?') {
                    lookahead_token = token_type::query;
                } else if (c == '#') {
                    lookahead_token = token_type::fragment;
                }
            } else {
                authority_end = uri.size();
            }

            if (authority_end > i) {
                // The substring starts on 0 to ensure that indices are correct
                authority_substr = uri.substr(0, authority_end);
                if (authority_substr.find('@', i) != npos) {
                    expected_token = token_type::userinfo;
                } else {
                    expected_token = token_type::host;
                }

                decomposed.authority.index = token_begin;
                decomposed.authority.raw = uri.substr(token_begin, authority_end - token_begin);
                decomposed.scheme_and_authority = uri.substr(0, authority_end);
            } else {
                expected_token = lookahead_token;
            }

            break;
        }
        case token_type::userinfo: {
            auto token_begin = i;
            // Find any unexpected characters, technically the ':' is valid and the
            // password is deprecated so allow one or more instances of it.
            while (i < uri.size()) {
                const auto c = uri[i++];

                if (c == '@') {
                    // If we find ourselves in this token, the @ is guaranteed
                    // to be present.
                    decomposed.authority.userinfo = uri.substr(token_begin, i - token_begin - 1);
                    if (i == authority_end) {
                        expected_token = lookahead_token;
                    } else {
                        expected_token = token_type::host;
                    }
                    break;
                }

                if (!is_userinfo_char(c)) {
                    // We've found an invalid character, we can consider the
                    // authority malformed
                    return std::nullopt;
                }
            }

            break;
        }
        case token_type::host: {
            if (uri[i] == '[') {
                expected_token = token_type::ipv6address;
            } else if (uri[i] == ':') { // Empty host
                ++i;
                expected_token = token_type::port;
            } else if (is_host_char(uri[i])) {
                expected_token = token_type::regname_or_ipv4address;
            } else if (authority_end != uri.size()) {
                expected_token = lookahead_token;
            } else {
                // Not a valid character, malformed
                return std::nullopt;
            }
            break;
        }
        case token_type::regname_or_ipv4address: {
            auto token_begin = i;
            // Reg name or IPv4 host
            for (; i < authority_end; ++i) {
                const auto c = uri[i];
                if (c == ':') { /* Port */
                    break;
                }
                if (!is_regname_char(c)) {
                    // Unexpected character, find the port  and exit
                    return std::nullopt;
                }
            }

            decomposed.authority.host = uri.substr(token_begin, i - token_begin);
            decomposed.authority.host_index = token_begin;

            ipaddr parsed_ip{};
            if (parse_ipv4(decomposed.authority.host, parsed_ip)) {
                ipv4_to_ipv6(parsed_ip);
                decomposed.authority.host_ip = parsed_ip;
            }

            if (i >= uri.size()) {
                return decomposed;
            }

            if (uri[i] == ':') {
                ++i;
                expected_token = token_type::port;
            } else {
                expected_token = lookahead_token;
            }
            break;
        }
        case token_type::ipv6address: {
            auto token_begin = i;
            // Validate if this is an IPv6 host
            bool end_found = false;
            for (i += 1; i < uri.size(); ++i) {
                const auto c = uri[i];
                if (c == ']') { /* IPv6 End */
                    end_found = true;
                    break;
                }
                if (!ddwaf::isxdigit(c) && c != ':') {
                    // The host is already malformed so we can stop here;
                    return std::nullopt;
                }
            }

            if (!end_found || i == (token_begin + 1)) {
                return std::nullopt;
            }

            ipaddr parsed_ip{};
            auto host = uri.substr(token_begin + 1, i - (token_begin + 1));
            if (!parse_ipv6(host, parsed_ip)) {
                return std::nullopt;
            }

            decomposed.authority.host = host;
            decomposed.authority.host_ip = parsed_ip;
            decomposed.authority.host_index = token_begin + 1;

            token_begin = ++i;
            if (token_begin == authority_end) {
                // Keep the next token as it can be the beginning of the
                // path which has to be kept
                expected_token = lookahead_token;
            } else if (i < uri.size() && uri[i] == ':') {
                ++i; // Skip the ':'
                expected_token = token_type::port;
            } else {
                // Unexpected characters after IPv6 terminator
                return std::nullopt;
            }

            break;
        }
        case token_type::port: {
            auto token_begin = i;
            for (; i < authority_end; ++i) {
                if (!ddwaf::isdigit(uri[i])) {
                    return std::nullopt;
                }
            }

            auto port_substr = uri.substr(token_begin, i - token_begin);
            if (!port_substr.empty()) {
                if (auto [res, value] = from_string<uint16_t>(port_substr); res) {
                    decomposed.authority.port = value;
                } else {
                    return std::nullopt;
                }
            }

            if (authority_end == uri.size()) {
                return decomposed;
            }

            expected_token = lookahead_token;

            break;
        }
        case token_type::path: {
            auto token_begin = i;
            for (; i < uri.size(); ++i) {
                const auto c = uri[i];
                if (c == '?') {
                    expected_token = token_type::query;
                    break;
                }

                if (c == '#') {
                    expected_token = token_type::fragment;
                    break;
                }

                if (!is_path_char(c) && c != '/') {
                    return std::nullopt;
                }
            }

            decomposed.path_index = token_begin;
            if (i >= uri.size()) {
                decomposed.path = decomposed.raw.substr(token_begin);
                return decomposed;
            }

            decomposed.path = decomposed.raw.substr(token_begin, i - token_begin);
            break;
        }
        case token_type::query: {
            // Skip '?'
            auto token_begin = ++i;
            for (; i < uri.size(); ++i) {
                const auto c = uri[i];
                if (c == '#') {
                    expected_token = token_type::fragment;
                    break;
                }

                if (!is_query_char(c)) {
                    return std::nullopt;
                }
            }

            // Ignore empty query
            if (i > token_begin) {
                decomposed.query_index = token_begin;
                if (i >= uri.size()) {
                    decomposed.query = decomposed.raw.substr(token_begin);
                    return decomposed;
                }

                decomposed.query = decomposed.raw.substr(token_begin, i - token_begin);
            }
            break;
        }
        case token_type::fragment: {
            // Skip '#'
            auto token_begin = ++i;
            for (; i < uri.size(); ++i) {
                const auto c = uri[i];
                if (!is_frag_char(c)) {
                    return std::nullopt;
                }
            }

            // Ignore empty fragment
            if (i > token_begin) {
                decomposed.fragment_index = token_begin;
                decomposed.fragment = uri.substr(token_begin);
            }
            return decomposed;
        }
        case token_type::none:
        default:
            return std::nullopt;
        }
    }

    return decomposed;
}

std::ostream &operator<<(std::ostream &o, const uri_decomposed &uri)
{
    o << "Scheme   : " << uri.scheme << '\n'
      << "Userinfo : " << uri.authority.userinfo << '\n'
      << "Host     : " << uri.authority.host << '\n'
      << "Port     : " << uri.authority.port << '\n'
      << "Path     : " << uri.path << '\n'
      << "Query    : " << uri.query << '\n'
      << "Fragment : " << uri.fragment << '\n';
    return o;
}
} // namespace ddwaf
