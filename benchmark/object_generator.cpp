// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#include <iostream>
#include <stack>
#include <yaml-cpp/yaml.h>

#include "object_generator.hpp"
#include "random.hpp"
#include "utils.hpp"
#include "yaml_helpers.hpp"

namespace utils = ddwaf::benchmark::utils;

namespace ddwaf::benchmark {

namespace {

constexpr unsigned max_terminal_nodes = 100;
constexpr unsigned max_intermediate_nodes = 500;
constexpr unsigned max_depth = 10;
constexpr unsigned max_string_length = 4096;
constexpr unsigned max_key_length = 128;

char *generate_random_string(std::size_t length)
{
    static const auto &charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                 "`¬|\\|,<.>/?;:'@#~[{]}=+-_)(*&^%$£\"\0!";

    // NOLINTNEXTLINE
    char *str = (char *)malloc(length + 1);
    for (std::size_t i = 0; i < length; i++) {
        str[i] = charset[random::get() % (sizeof(charset) - 2)];
    }
    str[length] = '\0';

    return str;
}

void generate_string_object(ddwaf_object &o)
{
    char *str = generate_random_string(max_string_length);
    ddwaf_object_stringl_nc(&o, str, max_string_length);
}

void generate_container(ddwaf_object &o) {
    if (random::get_bool()) {
        ddwaf_object_array(&o);
    } else {
        ddwaf_object_map(&o);
    }
}

struct level_nodes {
    unsigned intermediate{0};
    unsigned terminal{0};
};

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
std::vector<level_nodes> generate_node_distribution(unsigned nodes, unsigned intermediate, unsigned terminal)
{
    std::vector<level_nodes> levels;
    levels.resize(nodes);

    // Distribute intermediate nodes, this doesn't apply to the last level
    while (intermediate > 0) {
        for (unsigned i = 0; intermediate > 0 && i < (max_depth - 1); ++i) {
            auto extra_nodes = 1 + random::get(intermediate);
            levels[i].intermediate += extra_nodes;
            intermediate -= extra_nodes;
        }
    }

    while (terminal > 0) {
        for (unsigned i = 0; terminal > 0 && i < max_depth; ++i) {
            auto extra_nodes = 1 + random::get(terminal);
            levels[i].terminal += extra_nodes;
            terminal -= extra_nodes;
        }
    }

    return levels;
}

void generate_object(ddwaf_object &o)
{
    auto levels = generate_node_distribution(max_depth, max_intermediate_nodes, max_terminal_nodes);

    struct queue_node {
        ddwaf_object *object;
        unsigned level;
    };

    std::deque<queue_node> object_queue;
    generate_container(o);
    object_queue.emplace_back(&o, 0);

    for (; !object_queue.empty(); object_queue.pop_front()) {
        auto &node = object_queue.front();
        auto &next_nodes = levels[node.level];

        unsigned terminal = 0;
        unsigned intermediate = 0;
        if (node.level == 0) {
            terminal = next_nodes.terminal;
            intermediate = next_nodes.intermediate;
        } else {
            terminal = next_nodes.terminal > 0 ? 1 + random::get(next_nodes.terminal) : 0;
            intermediate = next_nodes.intermediate > 0 ? 1 + random::get(next_nodes.intermediate) : 0;
        }
        next_nodes.terminal -= terminal;
        next_nodes.intermediate -= intermediate;

        while ((terminal + intermediate) > 0) {
            ddwaf_object next;

            bool build_terminal = random::get_bool() ? terminal > 0 : intermediate == 0;

            if (build_terminal) {
                generate_string_object(next);
                --terminal;
            } else {
                generate_container(next);
                --intermediate;
            }

            if (node.object->type == DDWAF_OBJ_MAP) {
                auto *str = generate_random_string(max_key_length);
                ddwaf_object_map_addl_nc(node.object, str, max_key_length, &next);
            } else {
                ddwaf_object_array_add(node.object, &next);
            }
        }

        for (unsigned i = 0; i < node.object->nbEntries; ++i) {
            auto type = node.object->array[i].type;
            if (type == DDWAF_OBJ_MAP || type == DDWAF_OBJ_ARRAY) {
                object_queue.emplace_back(&node.object->array[i], node.level + 1);
            }
        }
    }
}

} // namespace

object_generator::object_generator(
    const std::vector<std::string_view> &addresses, const YAML::Node &spec)
{
    for (auto addr : addresses) { addresses_[addr] = {}; }

    const YAML::Node &test_vectors = spec["vectors"];
    if (!test_vectors) {
        return;
    }

    for (auto it = test_vectors.begin(); it != test_vectors.end(); ++it) {
        auto key = it->first.as<std::string>();
        auto &current_values = addresses_[key];

        auto array = it->second;
        for (auto value_it = array.begin(); value_it != array.end(); ++value_it) {
            auto vector = value_it->as<ddwaf_object>();
            objects_.push_back(vector);
            current_values.push_back(vector);
        }
    }
}

object_generator::~object_generator()
{
    for (auto &obj : objects_) { ddwaf_object_free(&obj); }
}

std::vector<ddwaf_object> object_generator::operator()(
    object_generator::generator_type type, size_t n) const
{
    std::vector<ddwaf_object> output(n);

    while (n-- > 0) {
        ddwaf_object &root = output[n];
        ddwaf_object_map(&root);

        for (const auto &[addr, valid_values] : addresses_) {
            ddwaf_object value;

            if (type == generator_type::valid) {
                if (valid_values.empty()) {
                    continue;
                }

                std::size_t index = random::get() % valid_values.size();
                value = utils::object_dup(valid_values[index]);
            } else {
                generate_object(value);
            }

            ddwaf_object_map_add(&root, addr.data(), &value);
        }
    }

    if (output.empty() && type == generator_type::valid) {
        throw std::runtime_error("No valid values available");
    }

    return output;
}

} // namespace ddwaf::benchmark

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
/*void print_help_and_exit(std::string_view name, std::string_view error = {})*/
/*{*/
    /*std::cerr << "Usage: " << name << " [OPTION]...\n"*/
              /*<< "    --scenarios VALUE     Scenarios repository path\n"*/
              /*<< "    --fixtures VALUE      Common fixtures repository path\n"*/
              /*<< "    --runs VALUE          Number of runs per scenario\n"*/
              /*<< "    --iterations VALUE    Number of iterations per run\n"*/
              /*<< "    --warmup VALUE        Number of warmup iterations per run\n"*/
              /*<< "    --format VALUE        Output format: csv, json, human, none\n"*/
              /*<< "    --output VALUE        Results output file\n";*/

    /*if (!error.empty()) {*/
        /*std::cerr << "\nError: " << error << "\n";*/
        /*utils::exit_failure();*/
    /*}*/
    /*utils::exit_success();*/
/*}*/

/*benchmark::settings generate_settings(const std::vector<std::string> &args)*/
/*{*/
    /*benchmark::settings s;*/

    /*auto opts = utils::parse_args(args);*/

    /*if (opts.contains("help")) {*/
        /*print_help_and_exit(args[0]);*/
    /*}*/

    /*if (!opts.contains("scenarios")) {*/
        /*print_help_and_exit(args[0], "Missing option --scenarios");*/
    /*} else {*/
        /*auto root = opts["scenarios"];*/
        /*if (fs::is_directory(root)) {*/
            /*for (const auto &dir_entry : fs::directory_iterator{root}) {*/
                /*const fs::path &scenario_path = dir_entry;*/

                /*if (is_regular_file(scenario_path) && scenario_path.extension() == ".json") {*/
                    /*s.scenarios.emplace_back(scenario_path);*/
                /*}*/
            /*}*/
        /*} else {*/
            /*s.scenarios.emplace_back(root);*/
        /*}*/
    /*}*/

    /*if (opts.contains("fixtures")) {*/
        /*auto root = opts["fixtures"];*/
        /*if (fs::is_directory(root)) {*/
            /*for (const auto &dir_entry : fs::directory_iterator{root}) {*/
                /*const fs::path &scenario_path = dir_entry;*/

                /*if (is_regular_file(scenario_path) && scenario_path.extension() == ".json") {*/
                    /*s.fixtures.emplace_back(scenario_path);*/
                /*}*/
            /*}*/
        /*} else {*/
            /*s.fixtures.emplace_back(root);*/
        /*}*/
    /*}*/

    /*if (opts.contains("format")) {*/
        /*auto format = opts["format"];*/
        /*if (format == "csv") {*/
            /*s.format = benchmark::output_fmt::csv;*/
        /*} else if (format == "human") {*/
            /*s.format = benchmark::output_fmt::human;*/
        /*} else if (format == "json") {*/
            /*s.format = benchmark::output_fmt::json;*/
        /*} else if (format == "none") {*/
            /*s.format = benchmark::output_fmt::none;*/
        /*} else {*/
            /*print_help_and_exit(args[0], "Unsupported value for --format");*/
        /*}*/
    /*}*/

    /*if (s.format != benchmark::output_fmt::none && opts.contains("output")) {*/
        /*s.output_file = opts["output"];*/
    /*}*/

    /*if (opts.contains("runs")) {*/
        /*s.runs = utils::from_string<unsigned>(opts["runs"]);*/
        /*if (s.runs == 0) {*/
            /*print_help_and_exit(args[0], "Runs should be a positive number");*/
        /*}*/
    /*}*/

    /*if (opts.contains("iterations")) {*/
        /*s.iterations = utils::from_string<unsigned>(opts["iterations"]);*/
        /*if (s.iterations == 0) {*/
            /*print_help_and_exit(args[0], "Iterations should be a positive number");*/
        /*}*/
    /*}*/

    /*if (opts.contains("warmup")) {*/
        /*s.warmup_iterations = utils::from_string<unsigned>(opts["warmup"]);*/
    /*}*/

    /*return s;*/
/*}*/

int main(int argc, char *argv[])
{
    std::vector<std::string> args(argv, argv + argc);
    auto s = utils::parse_args(args);

    return EXIT_SUCCESS;
}
