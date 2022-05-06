// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <yaml-cpp/yaml.h>

namespace fs = std::filesystem;

struct benchmark {
    struct result {
        double average, sd;
    };

    std::map<std::string, result> tests;
    double iterations;
};

namespace YAML
{

template <> struct as_if<benchmark::result, void> {
    explicit as_if(const Node &node_) : node(node_) {}
    benchmark::result operator()() const
    {
        return {
            node["average"].as<double>(),
            node["sd"].as<double>(),
        };
    }

    const Node &node;
};

template <> struct as_if<benchmark, void> {
    explicit as_if(const Node &node_) : node(node_) {}
    benchmark operator()() const
    {
        return {
            node["results"].as<decltype(benchmark::tests)>(),
            node["iterations"].as<double>(),
        };
    }

    const Node &node;
};

}

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

    auto baseline = read_yaml(base_file).as<benchmark>();
    auto latest = read_yaml(latest_file).as<benchmark>();

    std::size_t max_length = 0;
    for (auto &[test, b] : baseline.tests) {
        max_length = std::max(test.size(), max_length);
    }
    ++max_length;

    for (auto &[test, b] : baseline.tests) {
        auto it = latest.tests.find(test);
        if (it == latest.tests.end()) {
            continue;
        }
        auto &l = it->second;

        double avg_pct = 100.0 - ((l.average * 100.0) / b.average);

        double ztest = (l.average - b.average) /
            sqrt(b.sd * b.sd / baseline.iterations +
                 l.sd * l.sd / latest.iterations);

        std::cout << std::setw(max_length) << std::setfill(' ') << std::left
                  << test << ": "
                  << std::fixed << std::setprecision(2)
                  << avg_pct << "% " << (avg_pct < 0 ? "slower" : "faster")
                  << " than baseline, ";
        if (abs(ztest) < 2.0) {
            std::cout << "NOT statistically significant ";
        }
        std::cout << "(z-test: " << ztest << ")\n";
    }

    return EXIT_SUCCESS;
}
