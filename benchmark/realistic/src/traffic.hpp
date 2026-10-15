// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

// Deterministic generator of WAF calls modelled after dd-trace-php appsec
// (helper-rust): one context per request, an initial eval with the 10
// request_init addresses, an optional eval with framework route parameters,
// one transient subcontext per RASP hook / user event, and a final eval with
// the response addresses.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "node.hpp"

namespace bench {

struct step {
    bool subcontext{false}; // transient subcontext (init, eval, destroy)
    node data;              // map of address -> value
};

struct request_spec {
    std::vector<step> steps;
    bool attack{false};       // contains at least one injected payload
    bool expect_block{false}; // blocked IP or blocked user
};

enum class traffic_mix : uint8_t {
    small,      // typical small requests (pages, AJAX, small JSON API, logins)
    large,      // large bodies, many headers / cookies, long strings
    attack,     // small requests carrying attack payloads (incl. RASP exploits)
    rasp_heavy, // CMS-like page with dozens of SQL queries and file accesses
};

struct traffic_options {
    traffic_mix mix{traffic_mix::small};
    std::size_t count{256};
    uint64_t seed{1};
    // Values present in the loaded blocklists (exact entries, not expired).
    std::vector<std::string> blocked_ips;
    std::vector<std::string> blocked_users;
    unsigned blocked_ip_one_in{0};   // 1 in N requests comes from a blocked IP
    unsigned login_one_in{32};       // 1 in N requests is a login (user event)
    unsigned blocked_user_one_in{0}; // 1 in N logins is from a blocked user
};

std::vector<request_spec> generate_traffic(const traffic_options &opts);

} // namespace bench
