// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "uri_utils.hpp"
#include "utils.hpp"
#include <iostream>

namespace ddwaf {

namespace {
constexpr const auto &npos = std::string_view::npos;

inline bool isunreserved(char c)
{
    return ddwaf::isalnum(c) || c == '-' || c == '.' || c == '_' || c == '~';
}

inline bool issubdelim(char c)
{
    return c == '!' || c == '$' || c == '&' || c == '\'' || c == '(' || c == ')' || c == '*' ||
           c == '*' || c == '+' || c == ',' || c == ';' || c == '=';
}

// ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
inline bool isschemechar(char c) { return ddwaf::isalnum(c) || c == '.' || c == '-' || c == '+'; }

// *( unreserved / pct-encoded / sub-delims / ":" )
inline bool isuserinfochar(char c)
{
    return isunreserved(c) || issubdelim(c) || c == ':' || c == '%';
}

// *( unreserved / pct-encoded / sub-delims )
inline bool isregname(char c) { return isunreserved(c) || issubdelim(c) || c == '%'; }

} // namespace

std::optional<uri_decomposed> uri_parse(std::string_view uri)
{
    uri_decomposed decomposed;
    decomposed.raw = uri;

    // First find the scheme: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
    // https://datatracker.ietf.org/doc/html/rfc3986#section-3.1
    std::size_t i = 0;
    while (i < uri.size() && isschemechar(uri[i])) { ++i; }
    if (i == 0 || i >= uri.size() || uri[i] != ':') {
        return std::nullopt;
    }

    decomposed.scheme = uri.substr(0, i);

    std::size_t next_sep = ++i;
    if (next_sep >= uri.size()) {
        return decomposed;
    }

    bool authority_found = false;
    // Find the authority, which always starts with //
    // https://datatracker.ietf.org/doc/html/rfc3986#section-3.2
    if ((i + 1) < uri.size() && uri[i] == '/' && uri[i + 1] == '/') {
        i += 2; // Past '//'
        authority_found = true;
        next_sep = uri.find_first_of("/?#", i);
    }

    if (authority_found && next_sep != i) {
        // Non empty authority
        decomposed.authority.index = i;
        if (next_sep != npos) {
            // Discard everything after the authority
            uri = decomposed.scheme_and_authority = uri.substr(0, next_sep);
            decomposed.authority.raw = uri.substr(i, next_sep);
        } else {
            decomposed.scheme_and_authority = uri;
            decomposed.authority.raw = uri.substr(i);
        }

        // Identify userinfo, since the character ':' can correspond to both the
        // password delimiter or the port delimiter, we must search for @
        // https://datatracker.ietf.org/doc/html/rfc3986#section-3.2.1
        auto userinfo_end = uri.find('@', i);
        if (userinfo_end != npos) {
            decomposed.authority.userinfo = uri.substr(i, userinfo_end - i);
            // Find any unexpected characters, technically the ':' is valid and the
            // password is deprecated so allow one or more instances of it.
            // ALPHA / DIGIT / "-" / "." / "_" / "~" / "!" / "$" / "&" / "'" /
            // "(" / ")" / "*" / "+" / "," / ";" / "=" / "%"
            for (; i < userinfo_end; ++i) {
                // We've found an invalid character, we can consider the
                // authority malformed
                if (!isuserinfochar(uri[i])) {
                    return std::nullopt;
                }
            }
            i = userinfo_end + 1;
        }

        // Identify the (non-optional) host
        // https://datatracker.ietf.org/doc/html/rfc3986#section-3.2.2
        if (i < uri.size()) {
            auto host_begin = i;
            if (uri[i] == '[') {
                // Validate if this is an IPv6 host
                bool end_found = false;
                bool non_ip_chars = false;
                for (i += 1; i < uri.size(); ++i) {
                    const auto c = uri[i];
                    if (c == ']') { /* IPv6 End */
                        end_found = true;
                        break;
                    }
                    if (!ddwaf::isxdigit(c) && c != ':') {
                        // The host is already malformed so we can stop here;
                        non_ip_chars = true;
                        break;
                    }
                }
                if (!end_found || non_ip_chars || i == (host_begin + 1)) {
                    return std::nullopt;
                }

                // Valid IPv6, remove the []
                decomposed.authority.host = uri.substr(host_begin + 1, i - (host_begin + 1));
                decomposed.authority.host_index = host_begin + 1;
                decomposed.authority.ipv6_host = true;
                i += 1; // Past the host end ']'
            } else {
                // Reg name or IPv4 host
                for (; i < uri.size(); ++i) {
                    const auto c = uri[i];
                    if (c == ':') { /* Port */
                        break;
                    }
                    if (!isregname(c)) {
                        // Unexpected character, find the port  and exit
                        return std::nullopt;
                    }
                }
                if (i <= host_begin) {
                    // An empty host is a malformed authority however we might still
                    // be able to extract a port
                    return std::nullopt;
                }

                decomposed.authority.host = uri.substr(host_begin, i - host_begin);
                decomposed.authority.host_index = host_begin;
            }
        } else {
            // An empty host is a malformed authority
            return std::nullopt;
        }

        // Identify the (optional) port
        // https://datatracker.ietf.org/doc/html/rfc3986#section-3.2.3
        if (i < uri.size() && uri[i] == ':') {
            auto port_begin = ++i; // Skip ':'
            if (port_begin == uri.size()) {
                return std::nullopt;
            }

            for (; i < uri.size(); ++i) {
                if (!ddwaf::isdigit(uri[i])) {
                    return std::nullopt;
                }
            }
            decomposed.authority.port = uri.substr(port_begin);
        }
    }

    // Identify the path, fragment and query.
    // TODO: Add character validation
    if (next_sep != npos) {
        const auto c = decomposed.raw[next_sep];
        if ((authority_found && c == '/') || (!authority_found && c != '?' && c != '#')) {
            auto path_end = decomposed.raw.find_first_of("?#", next_sep);
            decomposed.path_index = next_sep;
            if (path_end != npos) {
                decomposed.path = decomposed.raw.substr(next_sep, path_end - next_sep);
            } else {
                decomposed.path = decomposed.raw.substr(next_sep);
            }
            next_sep = path_end;
        }
    }

    if (next_sep != npos && decomposed.raw[next_sep] == '?') {
        auto path_end = decomposed.raw.find_first_of('#', next_sep);
        decomposed.query_index = next_sep;
        if (path_end != npos) {
            decomposed.query = decomposed.raw.substr(next_sep + 1, path_end - (next_sep + 1));
        } else {
            decomposed.query = decomposed.raw.substr(next_sep + 1);
        }
        next_sep = path_end;
    }

    if (next_sep != npos && decomposed.raw[next_sep] == '#') {
        decomposed.fragment_index = next_sep;
        decomposed.fragment = decomposed.raw.substr(next_sep + 1);
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
