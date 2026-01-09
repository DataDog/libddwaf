// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include "common/utils.hpp"
#include "ddwaf.h"

#include <arpa/inet.h>
#include <chrono>
#include <cstdlib>
#include <random>
#include <sys/socket.h>
#include <unordered_set>

std::random_device dev;
std::mt19937 rng(dev());

std::string generate_random_ip()
{
    // IPv4
    if (rng() % 2 == 0) {
        sockaddr_in sa{};
        std::array<char, INET_ADDRSTRLEN> str{};

        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = rng();

        // now get it back and print it
        inet_ntop(AF_INET, &(sa.sin_addr), str.data(), INET_ADDRSTRLEN);

        return {str.data()};
    }

    sockaddr_in6 sa{};
    std::array<char, INET6_ADDRSTRLEN> str{};

    sa.sin6_family = AF_INET6;
    std::array<uint32_t, 4> addr_parts{rng(), rng(), rng(), rng()};
    std::memcpy(&sa.sin6_addr.s6_addr, addr_parts.data(), sizeof(addr_parts));

    inet_ntop(AF_INET6, &(sa.sin6_addr), str.data(), INET6_ADDRSTRLEN);

    return {str.data()};
}

std::vector<std::string> generate_ip_set(std::size_t length)
{
    std::vector<std::string> ip_set;
    for (std::size_t i = 0; i < length; i++) {
        ip_set.emplace_back(generate_random_ip());
    }
    return ip_set;
}

ddwaf_object generate_rule_data(const std::vector<std::string>& ip_set)
{
    auto alloc = ddwaf_get_default_allocator();
    ddwaf_object data;

    ddwaf_object_set_array(&data, ip_set.size(), alloc);

    for (const auto& ip : ip_set) {
        ddwaf_object *data_point = ddwaf_object_insert(&data, alloc);
        ddwaf_object_set_map(data_point, 2, alloc);

        ddwaf_object *expiration = ddwaf_object_insert_literal_key(data_point, "expiration", 10, alloc);
        ddwaf_object_set_unsigned(expiration, 0);

        ddwaf_object *value = ddwaf_object_insert_literal_key(data_point, "value", 5, alloc);
        ddwaf_object_set_string(value, ip.c_str(), ip.size(), alloc);
    }

    ddwaf_object rule_data;
    ddwaf_object_set_map(&rule_data, 3, alloc);

    ddwaf_object *id = ddwaf_object_insert_literal_key(&rule_data, "id", 2, alloc);
    ddwaf_object_set_string_literal(id, "blocked_ips", 11);

    ddwaf_object *type = ddwaf_object_insert_literal_key(&rule_data, "type", 4, alloc);
    ddwaf_object_set_string_literal(type, "ip_with_expiration", 18);

    ddwaf_object *data_ptr = ddwaf_object_insert_literal_key(&rule_data, "data", 4, alloc);
    *data_ptr = data;

    ddwaf_object rule_data_array;
    ddwaf_object_set_array(&rule_data_array, 1, alloc);

    ddwaf_object *rule_data_item = ddwaf_object_insert(&rule_data_array, alloc);
    *rule_data_item = rule_data;

    ddwaf_object root;
    ddwaf_object_set_map(&root, 1, alloc);

    ddwaf_object *rules_data = ddwaf_object_insert_literal_key(&root, "rules_data", 10, alloc);
    *rules_data = rule_data_array;

    return root;
}

int main(int argc, char *argv[])
{
    ddwaf_set_log_cb(log_cb, DDWAF_LOG_OFF);
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <json/yaml file>\n";
        return EXIT_FAILURE;
    }

    auto alloc = ddwaf_get_default_allocator();

    std::string rule_str = read_file(argv[1]);
    auto rule = YAML::Load(rule_str).as<ddwaf_object>();

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ddwaf_object_destroy(&rule, alloc);
    if (handle == nullptr) {
        std::cout << "Failed to load " << argv[1] << '\n';
        return EXIT_FAILURE;
    }

    constexpr uint64_t runs_per_size = 100;
    constexpr uint64_t ips_per_size = 1000;

    std::map<std::size_t, uint64_t> results;

    for (uint64_t size : {1, 10, 100, 1000, 5000, 10000, 15000, 20000, 30000, 40000, 50000, 100000, 200000, 300000, 400000, 500000, 1000000}) {
        results[size] = 0;
        for (unsigned run = 0; run < runs_per_size; ++run) {
            auto ip_set = generate_ip_set(size);

            auto rule_data = generate_rule_data(ip_set);
            ddwaf_destroy(handle);
            handle = ddwaf_init(&rule_data, nullptr);
            ddwaf_object_destroy(&rule_data, alloc);

            if (handle == nullptr) {
                std::cout << "Failed to load rule data\n";
                return EXIT_FAILURE;
            }

            for (uint64_t i = 0 ; i < ips_per_size; i++) {
                ddwaf_context context = ddwaf_context_init(handle, alloc);

                if (context == nullptr) {
                    ddwaf_destroy(handle);
                    return EXIT_FAILURE;
                }

                ddwaf_object input;
                ddwaf_object_set_map(&input, 1, alloc);

                if (i % 2 == 0) {
                    const auto &ip = ip_set[i % size];
                    ddwaf_object *client_ip = ddwaf_object_insert_literal_key(&input, "http.client_ip", 14, alloc);
                    ddwaf_object_set_string(client_ip, ip.c_str(), ip.size(), alloc);
                } else {
                    auto ip = generate_random_ip();
                    ddwaf_object *client_ip = ddwaf_object_insert_literal_key(&input, "http.client_ip", 14, alloc);
                    ddwaf_object_set_string(client_ip, ip.c_str(), ip.size(), alloc);
                }


                auto start = std::chrono::system_clock::now();
                ddwaf_context_eval(context, &input, alloc, nullptr, std::numeric_limits<uint32_t>::max());
                auto count = (std::chrono::system_clock::now() - start).count();

                ddwaf_object_destroy(&input, alloc);
                results[size] += count;

                ddwaf_context_destroy(context);
            }
        }
    }

    ddwaf_destroy(handle);

    auto denominator = runs_per_size * ips_per_size;
    for (auto &[k, v] : results) {
        std::cout << k << "\t" <<  v/denominator << '\n';
    }

    return EXIT_SUCCESS;
}
