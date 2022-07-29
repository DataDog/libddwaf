// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <utils.h>
#include <string_view>

namespace ddwaf {

struct ipaddr {
    uint8_t data[16]; // big endian
    uint8_t mask;
    enum class address_family {
        ipv4,
        ipv6,
        ipv4_mapped_ipv6,
    } type;
};

bool parse_ip(std::string_view ip, ipaddr& out);
void ipv4_to_ipv6(ipaddr& out);
bool parse_cidr(std::string_view ip, ipaddr& out);

}
