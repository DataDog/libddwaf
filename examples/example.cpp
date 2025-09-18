#include "ddwaf.h"
#include <iostream>
#include <string>
#include <string_view>
#include <yaml-cpp/yaml.h>

#define LONG_TIME 1000000

namespace {

// Convert a ddwaf_object to YAML recursively using the new object layout
YAML::Node object_to_yaml(const ddwaf_object &obj);

inline std::string_view string_from_object(const ddwaf_object &o)
{
    switch (o.type) {
    case DDWAF_OBJ_SMALL_STRING:
        return std::string_view{o.via.sstr.data, o.via.sstr.size};
    case DDWAF_OBJ_STRING:
    case DDWAF_OBJ_LITERAL_STRING:
        return std::string_view{o.via.str.ptr, o.via.str.size};
    default:
        return std::string_view{};
    }
}

YAML::Node object_to_yaml(const ddwaf_object &obj)
{
    switch (obj.type) {
    case DDWAF_OBJ_BOOL:
        return YAML::Node(obj.via.b8.val);
    case DDWAF_OBJ_SIGNED:
        return YAML::Node(static_cast<int64_t>(obj.via.i64.val));
    case DDWAF_OBJ_UNSIGNED:
        return YAML::Node(static_cast<uint64_t>(obj.via.u64.val));
    case DDWAF_OBJ_FLOAT:
        return YAML::Node(obj.via.f64.val);
    case DDWAF_OBJ_SMALL_STRING:
    case DDWAF_OBJ_STRING:
    case DDWAF_OBJ_LITERAL_STRING:
        return YAML::Node(std::string{string_from_object(obj)});
    case DDWAF_OBJ_ARRAY: {
        YAML::Node out(YAML::NodeType::Sequence);
        for (uint16_t i = 0; i < obj.via.array.size; ++i) {
            out.push_back(object_to_yaml(obj.via.array.ptr[i]));
        }
        return out;
    }
    case DDWAF_OBJ_MAP: {
        YAML::Node out(YAML::NodeType::Map);
        for (uint16_t i = 0; i < obj.via.map.size; ++i) {
            const auto &kv = obj.via.map.ptr[i];
            auto ksv = string_from_object(kv.key);
            out[std::string{ksv}] = object_to_yaml(kv.val);
        }
        return out;
    }
    case DDWAF_OBJ_INVALID:
    case DDWAF_OBJ_NULL:
    default:
        return {};
    }
}

// Build a ddwaf_object from YAML recursively using the new setters/insert API
bool yaml_to_object_inplace(const YAML::Node &node, ddwaf_object *out, ddwaf_allocator alloc)
{
    switch (node.Type()) {
    case YAML::NodeType::Null:
        return ddwaf_object_set_null(out) != nullptr;
    case YAML::NodeType::Scalar: {
        const auto &s = node.Scalar();
        return ddwaf_object_set_string(out, s.c_str(), static_cast<uint32_t>(s.size()), alloc) != nullptr;
    }
    case YAML::NodeType::Sequence: {
        if (ddwaf_object_set_array(out, static_cast<uint16_t>(node.size()), alloc) == nullptr) {
            return false;
        }
        for (const auto &child : node) {
            ddwaf_object *slot = ddwaf_object_insert(out, alloc);
            if (slot == nullptr) {return false; }
            if (!yaml_to_object_inplace(child, slot, alloc)) {return false; }
        }
        return true;
    }
    case YAML::NodeType::Map: {
        if (ddwaf_object_set_map(out, static_cast<uint16_t>(node.size()), alloc) == nullptr) {
            return false;
        }
        for (auto it = node.begin(); it != node.end(); ++it) {
            auto key = it->first.as<std::string>();
            ddwaf_object *slot = ddwaf_object_insert_key(out, key.c_str(), static_cast<uint32_t>(key.size()), alloc);
            if (slot == nullptr) { return false; }
            if (!yaml_to_object_inplace(it->second, slot, alloc)) { return false; }
        }
        return true;
    }
    case YAML::NodeType::Undefined:
    default:
        return ddwaf_object_set_invalid(out) != nullptr;
    }
}

} // namespace
int main()
{
  std::string waf_rule = R"(
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

    YAML::Node doc = YAML::Load(waf_rule);

    ddwaf_allocator alloc = ddwaf_get_default_allocator();

    ddwaf_object rule;
    if (!yaml_to_object_inplace(doc, &rule, alloc)) {
        std::cerr << "Failed to convert YAML ruleset to ddwaf_object\n";
        return EXIT_FAILURE;
    }

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
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
    if (ddwaf_object_set_map(&root, 2, alloc) == nullptr) {
        ddwaf_context_destroy(context);
        ddwaf_destroy(handle);
        return EXIT_FAILURE;
    }
    {
        ddwaf_object *v = ddwaf_object_insert_literal_key(&root, "arg1", 4, alloc);
        if (v == nullptr || ddwaf_object_set_string(v, "string 1", 8, alloc) == nullptr) {
            ddwaf_context_destroy(context);
            ddwaf_destroy(handle);
            return EXIT_FAILURE;
        }
    }
    {
        ddwaf_object *v = ddwaf_object_insert_literal_key(&root, "arg2", 4, alloc);
        if (v == nullptr || ddwaf_object_set_string(v, "string 2", 8, alloc) == nullptr) {
            ddwaf_context_destroy(context);
            ddwaf_destroy(handle);
            return EXIT_FAILURE;
        }
    }

    ddwaf_object ret;
    auto code = ddwaf_context_eval(context, &root, alloc, &ret, LONG_TIME);
    std::cout << "Output second run: " << code << '\n';
    YAML::Emitter out(std::cout);
    out.SetIndent(2);
    out.SetMapFormat(YAML::Block);
    out.SetSeqFormat(YAML::Block);
    out << object_to_yaml(ret);

    ddwaf_object_destroy(&ret, alloc);

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);

    return EXIT_SUCCESS;
}
