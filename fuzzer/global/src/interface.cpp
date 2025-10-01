// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstdlib>
#include <ddwaf.h>
#include <iostream>
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
    std::string what_;
};

namespace {
// NOLINTNEXTLINE(misc-no-recursion)
void node_to_ddwaf_object(ddwaf_object *root, const Node &node)
{
    auto *alloc = ddwaf_get_default_allocator();
    switch (node.Type()) {
    case NodeType::Sequence: {
        ddwaf_object_set_array(root, node.size(), alloc);
        for (auto it = node.begin(); it != node.end(); ++it) {
            auto *child = ddwaf_object_insert(root, alloc);
            node_to_ddwaf_object(child, *it);
        }
        return;
    }
    case NodeType::Map: {
        ddwaf_object_set_map(root, node.size(), alloc);
        for (auto it = node.begin(); it != node.end(); ++it) {
            auto key = it->first.as<std::string>();
            auto *child = ddwaf_object_insert_key(root, key.data(), key.size(), alloc);
            node_to_ddwaf_object(child, it->second);
        }
        return;
    }
    case NodeType::Scalar: {
        const std::string &value = node.Scalar();

        if (node.Tag() == "?") {
            try {
                ddwaf_object_set_unsigned(root, node.as<uint64_t>());
                return;
            } catch (...) {}

            try {
                ddwaf_object_set_signed(root, node.as<int64_t>());
                return;
            } catch (...) {}

            try {
                ddwaf_object_set_float(root, node.as<double>());
                return;
            } catch (...) {}

            try {
                if (!value.empty() && value[0] != 'Y' && value[0] != 'y' && value[0] != 'n' &&
                    value[0] != 'N') {
                    // Skip the yes / no variants of boolean
                    ddwaf_object_set_bool(root, node.as<bool>());
                    return;
                }
            } catch (...) {}
        }

        ddwaf_object_set_string(root, value.data(), value.size(), alloc);
        return;
    }
    case NodeType::Null: {
        ddwaf_object_set_null(root);
        return;
    }
    case NodeType::Undefined: {
        ddwaf_object_set_invalid(root);
        return;
    }
    }

    throw parsing_error("Invalid YAML node type");
}

} // namespace

template <> as_if<ddwaf_object, void>::as_if(const Node &node_) : node(node_) {}

template <> ddwaf_object as_if<ddwaf_object, void>::operator()() const
{
    ddwaf_object object;
    node_to_ddwaf_object(&object, node);
    return object;
}

} // namespace YAML

namespace {

ddwaf_object file_to_object(std::string_view filename)
{
    YAML::Node doc = YAML::Load(read_file(filename));
    return doc.as<ddwaf_object>();
}

} // namespace

ddwaf_handle init_waf()
{
    ddwaf_config config{
        {.key_regex =
                R"((p(ass)?w(or)?d|pass(_?phrase)?|secret|(api_?|private_?|public_?)key)|token|consumer_?(id|key|secret)|sign(ed|ature)|bearer|authorization)",
            .value_regex = R"(^(?:\d[ -]*?){13,16}$)"}};
    ddwaf_object rule = file_to_object("sample_rules.yml");
    ddwaf_object ruleset_info;
    ddwaf_handle handle = ddwaf_init(&rule, &config, &ruleset_info);
    ddwaf_object_destroy(&rule, ddwaf_get_default_allocator());
    ddwaf_object_destroy(&ruleset_info, ddwaf_get_default_allocator());
    return handle;
}

void run_waf(ddwaf_handle handle, ddwaf_object args, bool ephemeral, size_t timeLeftInUs)
{
    auto *alloc = ddwaf_get_default_allocator();

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    if (context == nullptr) {
        ddwaf_object_destroy(&args, alloc);
        return;
    }

    ddwaf_object res;
    if (ephemeral) {
        auto *subctx = ddwaf_subcontext_init(context);
        ddwaf_subcontext_eval(subctx, &args, alloc, &res, timeLeftInUs);
        ddwaf_subcontext_destroy(subctx);
    } else {
        ddwaf_context_eval(context, &args, alloc, &res, timeLeftInUs);
    }

    // TODO split input in several ddwaf_object, and call ddwaf_context_eval on the same context

    ddwaf_object_destroy(&res, alloc);
    ddwaf_context_destroy(context);
}
