// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <array>
#include <cstring>
#include <stdexcept>
#include <string_view>

#include "log.hpp"
#include "matcher/geo_match.hpp"

namespace ddwaf::matcher {

namespace {

std::string get_country_from_entry(MMDB_entry_data_list_s *entry)
{
    // Hardcoded expected lookup:
    //  {
    //    "country":
    //     {
    //       "iso_code":
    //         "GB" <utf8_string>
    //     }
    //  }

    if (entry->entry_data.type != MMDB_DATA_TYPE_MAP || entry->entry_data.data_size == 0) {
        return {};
    }

    entry = entry->next;
    if (MMDB_DATA_TYPE_UTF8_STRING != entry->entry_data.type) {
        return {};
    }

    std::string_view key{
        entry->entry_data.utf8_string, static_cast<std::size_t>(entry->entry_data.data_size)};
    if (key != "country") {
        return {};
    }

    entry = entry->next;
    if (entry->entry_data.type != MMDB_DATA_TYPE_MAP || entry->entry_data.data_size == 0) {
        return {};
    }

    entry = entry->next;
    key = std::string_view{
        entry->entry_data.utf8_string, static_cast<std::size_t>(entry->entry_data.data_size)};
    if (key != "iso_code") {
        return {};
    }

    entry = entry->next;
    if (MMDB_DATA_TYPE_UTF8_STRING != entry->entry_data.type) {
        return {};
    }

    return {entry->entry_data.utf8_string, static_cast<std::size_t>(entry->entry_data.data_size)};
}

} // namespace

std::pair<bool, std::string> geo_match::match_impl(std::string_view str) const
{
    std::array<char, INET6_ADDRSTRLEN> ip_cstr{0};
    memcpy(ip_cstr.data(), str.data(), str.size());

    int gai_error;
    int mmdb_error;
    auto result = MMDB_lookup_string(&mmdb_, ip_cstr.data(), &gai_error, &mmdb_error);
    if (!result.found_entry || gai_error != 0 || mmdb_error != MMDB_SUCCESS) {
        return {false, {}};
    }

    MMDB_entry_data_list_s *entry_data_list = nullptr;
    int status = MMDB_get_entry_data_list(&result.entry, &entry_data_list);
    if (status != MMDB_SUCCESS || entry_data_list == nullptr) {
        MMDB_free_entry_data_list(entry_data_list);
        return {false, {}};
    }

    auto country = get_country_from_entry(entry_data_list);
    MMDB_free_entry_data_list(entry_data_list);
    if (countries_.contains(country)) {
        return {true, std::string{country}};
    }

    return {false, {}};
}

} // namespace ddwaf::matcher
