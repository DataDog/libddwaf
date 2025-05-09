// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstdlib>
#include <ddwaf.h>
#include <stdexcept>
#include <utility>
#include <yaml-cpp/yaml.h>

#include "helpers.hpp"
#include "interface.hpp"

namespace YAML {

class parsing_error : public std::exception {
public:
    explicit parsing_error(std::string what) : what_(std::move(what)) {}
    [[nodiscard]] const char *what() const noexcept override { return what_.c_str(); }

protected:
    const std::string what_;
};

// NOLINTNEXTLINE(misc-no-recursion)
ddwaf_object yaml_to_object(const Node &node)
{
    switch (node.Type()) {
    case NodeType::Sequence: {
        ddwaf_object arg;
        ddwaf_object_array(&arg);
        for (auto it = node.begin(); it != node.end(); ++it) {
            ddwaf_object child = yaml_to_object(*it);
            ddwaf_object_array_add(&arg, &child);
        }
        return arg;
    }
    case NodeType::Map: {
        ddwaf_object arg;
        ddwaf_object_map(&arg);
        for (auto it = node.begin(); it != node.end(); ++it) {
            auto key = it->first.as<std::string>();
            ddwaf_object child = yaml_to_object(it->second);
            ddwaf_object_map_addl(&arg, key.c_str(), key.size(), &child);
        }
        return arg;
    }
    case NodeType::Scalar: {
        const std::string &value = node.Scalar();
        ddwaf_object arg;
        ddwaf_object_stringl(&arg, value.c_str(), value.size());
        return arg;
    }
    case NodeType::Null:
    case NodeType::Undefined: {
        ddwaf_object arg;
        ddwaf_object_invalid(&arg);
        return arg;
    }
    }

    throw parsing_error("Invalid YAML node type");
}

template <> as_if<ddwaf_object, void>::as_if(const Node &node_) : node(node_) {}

template <> ddwaf_object as_if<ddwaf_object, void>::operator()() const
{
    return yaml_to_object(node);
}
} // namespace YAML

ddwaf_object file_to_object(std::string_view filename)
{
    YAML::Node doc = YAML::Load(read_file(filename));
    return doc.as<ddwaf_object>();
}

ddwaf_handle init_waf()
{
    ddwaf_config config{
        {.key_regex =
                R"((p(ass)?w(or)?d|pass(_?phrase)?|secret|(api_?|private_?|public_?)key)|token|consumer_?(id|key|secret)|sign(ed|ature)|bearer|authorization)",
            .value_regex = R"(^(?:\d[ -]*?){13,16}$)"},
        ddwaf_object_free};
    ddwaf_object rule = file_to_object("sample_rules.yml");
    ddwaf_object ruleset_info;
    ddwaf_handle handle = ddwaf_init(&rule, &config, &ruleset_info);
    ddwaf_object_free(&rule);
    ddwaf_object_free(&ruleset_info);
    return handle;
}

void run_waf(ddwaf_handle handle, ddwaf_object args, bool ephemeral, size_t timeLeftInUs)
{
    ddwaf_context context = ddwaf_context_init(handle);
    if (context == nullptr) {
        __builtin_trap();
    }

    ddwaf_object res;
    auto code = DDWAF_OK;
    if (ephemeral) {
        ddwaf_run(context, nullptr, &args, &res, timeLeftInUs);
    } else {
        ddwaf_run(context, &args, nullptr, &res, timeLeftInUs);
    }

    // TODO split input in several ddwaf_object, and call ddwaf_run on the same context

    if (code == DDWAF_ERR_INTERNAL) {
        __builtin_trap();
    }

    ddwaf_object_free(&res);
    ddwaf_context_destroy(context);
}
