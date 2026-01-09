#include "ddwaf.h"
#include <iostream>
#include <yaml-cpp/yaml.h>

#define LONG_TIME 1000000

namespace YAML {

template <> struct as_if<ddwaf_object, void> {
    explicit as_if(const Node &node_) : node(node_) {}

    static ddwaf_object yaml_to_object_helper(const Node &node, ddwaf_allocator alloc)
    {
        ddwaf_object arg;
        switch (node.Type()) {
        case NodeType::Sequence:
            ddwaf_object_set_array(&arg, 0, alloc);
            break;
        case NodeType::Map:
            ddwaf_object_set_map(&arg, 0, alloc);
            break;
        case NodeType::Scalar:
            {
                auto scalar = node.Scalar();
                ddwaf_object_set_string(&arg, scalar.c_str(), scalar.size(), alloc);
            }
            break;
        case NodeType::Null:
            ddwaf_object_set_null(&arg);
            break;
        case NodeType::Undefined:
        default:
            ddwaf_object_set_invalid(&arg);
            break;
        }
        return arg;
    }

    ddwaf_object operator()() const
    {
        auto alloc = ddwaf_get_default_allocator();
        std::list<std::tuple<ddwaf_object *, YAML::Node, YAML::Node::const_iterator>> stack;

        ddwaf_object root = yaml_to_object_helper(node, alloc);
        if (root.type == DDWAF_OBJ_MAP || root.type == DDWAF_OBJ_ARRAY) {
            stack.emplace_back(&root, node, node.begin());
        }

        while (!stack.empty()) {
            auto current_depth = stack.size();
            auto &[parent_obj, parent_node, it] = stack.back();

            for (; it != parent_node.end(); ++it) {
                YAML::Node child_node = parent_node.IsMap() ? it->second : *it;
                auto child_obj = yaml_to_object_helper(child_node, alloc);
                ddwaf_object *child_ptr = nullptr;
                if (parent_obj->type == DDWAF_OBJ_MAP) {
                    auto key = it->first.as<std::string>();
                    child_ptr = ddwaf_object_insert_key(parent_obj, key.c_str(), key.size(), alloc);
                    *child_ptr = child_obj;
                } else if (parent_obj->type == DDWAF_OBJ_ARRAY) {
                    child_ptr = ddwaf_object_insert(parent_obj, alloc);
                    *child_ptr = child_obj;
                }

                if (child_obj.type == DDWAF_OBJ_MAP || child_obj.type == DDWAF_OBJ_ARRAY) {
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
        output = ddwaf_object_get_bool(&obj);
        break;
    case DDWAF_OBJ_SIGNED:
        output = ddwaf_object_get_signed(&obj);
        break;
    case DDWAF_OBJ_UNSIGNED:
        output = ddwaf_object_get_unsigned(&obj);
        break;
    case DDWAF_OBJ_FLOAT:
        output = ddwaf_object_get_float(&obj);
        break;
    case DDWAF_OBJ_STRING:
    case DDWAF_OBJ_LITERAL_STRING:
    case DDWAF_OBJ_SMALL_STRING:
        {
            size_t length;
            const char* str = ddwaf_object_get_string(&obj, &length);
            output = std::string{str, length};
        }
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

        size_t size = ddwaf_object_get_size(&parent_obj);
        for (; index < size; ++index) {
            const ddwaf_object *child_obj = nullptr;
            if (parent_obj.type == DDWAF_OBJ_MAP) {
                child_obj = ddwaf_object_at_value(&parent_obj, index);
                auto *key_obj = ddwaf_object_at_key(&parent_obj, index);
                size_t key_len;
                const char* key_str = ddwaf_object_get_string(key_obj, &key_len);
                std::string key{key_str, key_len};

                auto child_node = object_to_yaml_helper(*child_obj);
                parent_node[key] = child_node;

                if (child_obj->type == DDWAF_OBJ_MAP || child_obj->type == DDWAF_OBJ_ARRAY) {
                    stack.emplace_back(*child_obj, child_node, 0);
                    ++index;
                    break;
                }
            } else if (parent_obj.type == DDWAF_OBJ_ARRAY) {
                child_obj = ddwaf_object_at_value(&parent_obj, index);
                auto child_node = object_to_yaml_helper(*child_obj);
                parent_node.push_back(child_node);

                if (child_obj->type == DDWAF_OBJ_MAP || child_obj->type == DDWAF_OBJ_ARRAY) {
                    stack.emplace_back(*child_obj, child_node, 0);
                    ++index;
                    break;
                }
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
    auto alloc = ddwaf_get_default_allocator();

    YAML::Node doc = YAML::Load(waf_rule.data());

    auto rule = doc.as<ddwaf_object>();
    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ddwaf_object_destroy(&rule, alloc);
    if (handle == nullptr) {
        return EXIT_FAILURE;
    }

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    if (context == nullptr) {
        ddwaf_destroy(handle);
        return EXIT_FAILURE;
    }

    ddwaf_object root;
    ddwaf_object_set_map(&root, 2, alloc);

    ddwaf_object *arg1 = ddwaf_object_insert_literal_key(&root, "arg1", 4, alloc);
    ddwaf_object_set_string_literal(arg1, "string 1", 8);

    ddwaf_object *arg2 = ddwaf_object_insert_literal_key(&root, "arg2", 4, alloc);
    ddwaf_object_set_string_literal(arg2, "string 2", 8);

    ddwaf_object ret;
    auto code = ddwaf_context_eval(context, &root, alloc, &ret, LONG_TIME);
    std::cout << "Output second run: " << code << '\n';
    if (code == DDWAF_MATCH) {
        YAML::Emitter out(std::cout);
        out.SetIndent(2);
        out.SetMapFormat(YAML::Block);
        out.SetSeqFormat(YAML::Block);
        out << object_to_yaml(ret);
    }

    ddwaf_object_destroy(&ret, alloc);

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);

    return EXIT_SUCCESS;
}
