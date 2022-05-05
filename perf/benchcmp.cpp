// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <yaml-cpp/yaml.h>

namespace fs = std::filesystem;

namespace {
std::string read_file(const fs::path &filename)
{
    std::ifstream file(filename.c_str(), std::ios::in);
    if (!file) {
        throw std::system_error(errno, std::generic_category());
    }

    // Create a buffer equal to the file size
    std::string buffer;
    file.seekg(0, std::ios::end);
    buffer.resize(file.tellg());
    file.seekg(0, std::ios::beg);

    file.read(&buffer[0], static_cast<int64_t>(buffer.size()));
    file.close();
    return buffer;
}

YAML::Node read_yaml(const fs::path &filename)
{
    std::string contents = read_file(filename);
    return YAML::Load(contents);
}

void print_help_and_exit(std::string_view name, std::string_view error = {})
{
    std::cerr << "Usage: " << name << " <baseline> <latest>\n";
    if (!error.empty()) {
        std::cerr << "\nError: " << error << "\n";
        exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
}

void validate(const YAML::Node &baseline, const YAML::Node &latest)
{
    if (baseline["seed"].as<uint64_t>() != latest["seed"].as<uint64_t>()) {
        std::cerr << "Test seed does not match\n";
        return;
    }

    auto base_last = baseline["last_random_value"].as<uint64_t>();
    auto latest_last = latest["last_random_value"].as<uint64_t>();
    if (base_last != latest_last) {
        auto base_iterations = baseline["iterations"].as<uint64_t>();
        auto latest_iterations = latest["iterations"].as<uint64_t>();

        std::cerr << "Tests might not be comparable: ";

        if (base_iterations != latest_iterations) {
            std::cerr << "different number of iterations\n";
        } else {
            std::cerr << "inconsistent mt19937 implementations\n";
        }
    }
}

} // namespace

int main(int argc, char *argv[])
{
    if (argc < 3) {
        print_help_and_exit(argv[0]);
    }

    fs::path base_file = argv[1];
    fs::path latest_file = argv[2];

    if (!fs::is_regular_file(base_file)) {
        print_help_and_exit(argv[0], "'baseline' is not a regular file\n");
    }

    if (!fs::is_regular_file(latest_file)) {
        print_help_and_exit(argv[0], "'latest' is not a regular file\n");
    }

    auto baseline = read_yaml(base_file);
    auto latest = read_yaml(latest_file);

    validate(baseline, latest);

    double total_pct = 0.0;

    auto base_results = baseline["results"];
    auto latest_results = latest["results"];
    for (auto it = base_results.begin(); it != base_results.end(); ++it) {
        try {
            auto b_res = it->second;
            auto l_res = latest_results[it->first.as<std::string>()];

            auto b_average = b_res["average"].as<double>();
            auto l_average = l_res["average"].as<double>();

            double avg_pct = 100.0 - ((l_average * 100.0) / b_average);

            total_pct += avg_pct;

            std::cout << it->first << ": " << std::fixed << std::setprecision(2)
                      << avg_pct << "%\n";
        } catch (...) {
            continue;
        }
    }

    std::cout << "total: " << std::fixed << std::setprecision(2)
              << total_pct / base_results.size() << "%\n";

    return EXIT_SUCCESS;
}
