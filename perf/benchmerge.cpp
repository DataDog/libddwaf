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
    std::map<std::string, std::vector<uint64_t>> samples;
    uint64_t iterations{0};
};

namespace YAML
{

template <> struct as_if<benchmark, void> {
    explicit as_if(const Node &node_) : node(node_) {}
    benchmark operator()() const
    {
        auto results = node["results"].as<std::map<std::string, Node>>();
        std::map<std::string, std::vector<uint64_t>> samples;

        for (auto &[key, value]: results) {
            samples[key] = value["samples"].as<std::vector<uint64_t>>();
        }
        return {samples, node["iterations"].as<double>()};
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
    std::cerr << "Usage: " << name << " <output> <result_0>...<result_n>\n";
    if (!error.empty()) {
        std::cerr << "\nError: " << error << "\n";
        exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
}

std::pair<uint64_t, uint64_t>  average_and_sd(const std::vector<uint64_t> &values)
{
    double average = 0.0, sd = 0.0;
    for (auto v : values) { average += v; }
    average /= values.size();
    for (auto v : values) { sd += (v - average) * (v - average); }
    return {average, sqrt(sd / values.size())};
}

void output_json(std::ostream &o, const benchmark &res)
{
    // Lazy JSON
    bool start = false;

    o  << R"({"iterations":)" << res.iterations << R"(,"results":{)";
    for (const auto &[k, v] : res.samples) {
        if (start) {
            o << ",";
        } else {
            start = true;
        }

        auto [average, sd] = average_and_sd(v);

        o << R"(")" << k << R"(":{)"
          << R"("average":)" << average << ","
          << R"("sd":)" << sd
          << "}";
    }
    o << "}}" << std::endl;
}


} // namespace

int main(int argc, char *argv[])
{
    if (argc < 3) {
        print_help_and_exit(argv[0]);
    }

    fs::path output_file = argv[1];

    benchmark final_result;
    for (int i = 2; i < argc; i++) {
        fs::path file = argv[i];

        if (!fs::is_regular_file(file)) {
            print_help_and_exit(argv[0], "test file is not a regular file\n");
        }

        auto result = read_yaml(file).as<benchmark>();
        final_result.iterations += result.iterations;
        for (auto &[k, v] : result.samples) {
            auto &samples = final_result.samples;
            if (samples.find(k) == samples.end()) {
                samples[k] = {};
            }

            auto &vec = samples[k];
            vec.resize(vec.size() + v.size());
            vec.insert(vec.end(), v.begin(), v.end());
        }
    }

    std::ofstream fout(output_file);
    output_json(fout, final_result);

    return EXIT_SUCCESS;
}
