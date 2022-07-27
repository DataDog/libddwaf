// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <utils.h>
#include <radixlib.h>

namespace ddwaf {

struct ipaddr {
    uint8_t data[16]; // big endian
    enum class address_family {
        ipv4,
        ipv6,
    } type;
};

bool parse_ip(const char* str, ipaddr& parsed);
void ipv4_to_ipv6(ipaddr& parsed);
bool parse_cidr(const char* str, size_t length, prefix_t& prefix);

}
