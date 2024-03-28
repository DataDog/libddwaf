#include "ddwaf.h"
#include <iostream>
#include <yaml-cpp/yaml.h>

#define LONG_TIME 1000000

namespace YAML {

template <> struct as_if<ddwaf_object, void> {
    explicit as_if(const Node &node_) : node(node_) {}

    static ddwaf_object yaml_to_object_helper(const Node &node)
    {
        ddwaf_object arg;
        switch (node.Type()) {
        case NodeType::Sequence:
            ddwaf_object_array(&arg);
            break;
        case NodeType::Map:
            ddwaf_object_map(&arg);
            break;
        case NodeType::Scalar:
            ddwaf_object_string(&arg, node.Scalar().c_str());
            break;
        case NodeType::Null:
            ddwaf_object_null(&arg);
            break;
        case NodeType::Undefined:
        default:
            ddwaf_object_invalid(&arg);
            break;
        }
        return arg;
    }

    ddwaf_object operator()() const
    {
        std::list<std::tuple<ddwaf_object &, YAML::Node, YAML::Node::const_iterator>> stack;

        ddwaf_object root = yaml_to_object_helper(node);
        if (root.type == DDWAF_OBJ_MAP || root.type == DDWAF_OBJ_ARRAY) {
            stack.emplace_back(root, node, node.begin());
        }

        while (!stack.empty()) {
            auto current_depth = stack.size();
            auto &[parent_obj, parent_node, it] = stack.back();

            for (; it != parent_node.end(); ++it) {
                YAML::Node child_node = parent_node.IsMap() ? it->second : *it;
                auto child_obj = yaml_to_object_helper(child_node);
                if (parent_obj.type == DDWAF_OBJ_MAP) {
                    auto key = it->first.as<std::string>();
                    ddwaf_object_map_add(&parent_obj, key.c_str(), &child_obj);
                } else if (parent_obj.type == DDWAF_OBJ_ARRAY) {
                    ddwaf_object_array_add(&parent_obj, &child_obj);
                }

                if (child_obj.type == DDWAF_OBJ_MAP || child_obj.type == DDWAF_OBJ_ARRAY) {
                    auto &child_ptr = parent_obj.array[parent_obj.nbEntries - 1];
                    stack.emplace_back(child_ptr, child_node, child_node.begin());
                    ++it;
                    break;
                }
            }

            if (current_depth == stack.size()) {
                stack.pop_back();
            }
        }
        return root;
    }

    const Node &node;
};

} // namespace YAML

namespace {

YAML::Node object_to_yaml_helper(const ddwaf_object &obj)
{
    YAML::Node output;
    switch (obj.type) {
    case DDWAF_OBJ_BOOL:
        output = obj.boolean;
        break;
    case DDWAF_OBJ_SIGNED:
        output = obj.intValue;
        break;
    case DDWAF_OBJ_UNSIGNED:
        output = obj.uintValue;
        break;
    case DDWAF_OBJ_FLOAT:
        output = obj.f64;
        break;
    case DDWAF_OBJ_STRING:
        output = std::string{obj.stringValue, obj.nbEntries};
        break;
    case DDWAF_OBJ_MAP:
        output = YAML::Load("{}");
        break;
    case DDWAF_OBJ_ARRAY:
        output = YAML::Load("[]");
        break;
    case DDWAF_OBJ_INVALID:
    case DDWAF_OBJ_NULL:
        output = YAML::Null;
        break;
    };
    return output;
}

} // namespace

YAML::Node object_to_yaml(const ddwaf_object &obj)
{
    std::list<std::tuple<const ddwaf_object &, YAML::Node, std::size_t>> stack;

    YAML::Node root = object_to_yaml_helper(obj);
    if (obj.type == DDWAF_OBJ_MAP || obj.type == DDWAF_OBJ_ARRAY) {
        stack.emplace_back(obj, root, 0);
    }

    while (!stack.empty()) {
        auto current_depth = stack.size();
        auto &[parent_obj, parent_node, index] = stack.back();

        for (; index < parent_obj.nbEntries; ++index) {
            auto &child_obj = parent_obj.array[index];
            auto child_node = object_to_yaml_helper(child_obj);

            if (parent_obj.type == DDWAF_OBJ_MAP) {
                std::string key{child_obj.parameterName, child_obj.parameterNameLength};
                parent_node[key] = child_node;
            } else if (parent_obj.type == DDWAF_OBJ_ARRAY) {
                parent_node.push_back(child_node);
            }

            if (child_obj.type == DDWAF_OBJ_MAP || child_obj.type == DDWAF_OBJ_ARRAY) {
                stack.emplace_back(child_obj, child_node, 0);
                ++index;
                break;
            }
        }

        if (current_depth == stack.size()) {
            stack.pop_back();
        }
    }
    return root;
}

constexpr std::string_view waf_rule = R"(
version: "2.1"
rules:
  - id: "1"
    name: rule 1
    tags:
      type: flow1
      category: test
    conditions:
      - operator: match_regex
        parameters:
          inputs:
            - address: arg1
          regex: .*
      - operator: match_regex
        parameters:
          inputs:
            - address: arg2
          regex: .*
    on_match: [ block ]
)";

int main()
{
    YAML::Node doc = YAML::Load(waf_rule.data());

    auto rule = doc.as<ddwaf_object>(); //= convert_yaml_to_args(doc);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ddwaf_object_free(&rule);
    if (handle == nullptr) {
        return EXIT_FAILURE;
    }

    ddwaf_context context = ddwaf_context_init(handle);
    if (handle == nullptr) {
        ddwaf_destroy(handle);
        return EXIT_FAILURE;
    }

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "arg1", ddwaf_object_string(&tmp, "string 1"));
    ddwaf_object_map_add(&root, "arg2", ddwaf_object_string(&tmp, "string 2"));

    ddwaf_result ret;
    auto code = ddwaf_run(context, &root, nullptr, &ret, LONG_TIME);
    std::cout << "Output second run: " << code << '\n';
    if (code == DDWAF_MATCH) {
        YAML::Emitter out(std::cout);
        out.SetIndent(2);
        out.SetMapFormat(YAML::Block);
        out.SetSeqFormat(YAML::Block);
        out << object_to_yaml(ret.events);
        out << object_to_yaml(ret.actions);
    }

    ddwaf_result_free(&ret);

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);

    return EXIT_SUCCESS;
}
