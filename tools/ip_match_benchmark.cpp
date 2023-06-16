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
    sa.sin6_addr.s6_addr32[0] = rng();
    sa.sin6_addr.s6_addr32[1] = rng();
    sa.sin6_addr.s6_addr32[2] = rng();
    sa.sin6_addr.s6_addr32[3] = rng();

    // now get it back and print it
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
    ddwaf_object tmp;
    ddwaf_object data;

    ddwaf_object_array(&data);

    for (const auto& ip : ip_set) {
        ddwaf_object data_point;
        ddwaf_object_map(&data_point);
        ddwaf_object_map_add(&data_point, "expiration", ddwaf_object_unsigned_force(&tmp, 0));

        ddwaf_object_map_add(&data_point, "value", ddwaf_object_stringl(&tmp, ip.c_str(), ip.size()));

        //std::cout << ip << std::endl;
        ddwaf_object_array_add(&data, &data_point);
    }

    ddwaf_object rule_data;
    ddwaf_object_map(&rule_data);
    ddwaf_object_map_add(&rule_data, "id", ddwaf_object_string(&tmp, "blocked_ips"));
    ddwaf_object_map_add(&rule_data, "type", ddwaf_object_string(&tmp, "ip_with_expiration"));
    ddwaf_object_map_add(&rule_data, "data", &data);

    ddwaf_object rule_data_array;
    ddwaf_object_array(&rule_data_array);
    ddwaf_object_array_add(&rule_data_array, &rule_data);


    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "rules_data", &rule_data_array);

    return root;
}

int main(int argc, char *argv[])
{
    ddwaf_set_log_cb(log_cb, DDWAF_LOG_OFF);
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <json/yaml file>\n";
        return EXIT_FAILURE;
    }

    std::string rule_str = read_file(argv[1]);
    auto rule = YAML::Load(rule_str).as<ddwaf_object>();

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};
    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ddwaf_object_free(&rule);
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

            auto update = generate_rule_data(ip_set);
            ddwaf_handle updated_handle = ddwaf_update(handle, &update, nullptr);
            ddwaf_object_free(&update);

            if (updated_handle == nullptr) {
                std::cout << "Failed to load rule data\n";
                return EXIT_FAILURE;
            }

            ddwaf_destroy(handle);
            handle = updated_handle;

            for (uint64_t i = 0 ; i < ips_per_size; i++) {
                ddwaf_context context = ddwaf_context_init(handle);

                if (context == nullptr) {
                    ddwaf_destroy(handle);
                    return EXIT_FAILURE;
                }

                ddwaf_object tmp;
                ddwaf_object input;
                ddwaf_object_map(&input);

                if (i % 2 == 0) {
                    const auto &ip = ip_set[i % size];
                    ddwaf_object_map_add(&input, "http.client_ip", ddwaf_object_stringl(&tmp, ip.c_str(), ip.size()));
                } else {
                    auto ip = generate_random_ip();
                    ddwaf_object_map_add(&input, "http.client_ip", ddwaf_object_stringl(&tmp, ip.c_str(), ip.size()));
                }


                auto start = std::chrono::system_clock::now();
                ddwaf_run(context, &input, nullptr, std::numeric_limits<uint32_t>::max());
                auto count = (std::chrono::system_clock::now() - start).count();

                ddwaf_object_free(&input);
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
