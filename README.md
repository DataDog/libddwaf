[![Build](https://github.com/DataDog/libddwaf/actions/workflows/build.yml/badge.svg)](https://github.com/DataDog/libddwaf/actions/workflows/build.yml)

# Datadog's WAF

``libddwaf`` is Datadog's implementation of a Web Application Firewall (WAF) engine, with a goal of low performance and memory overhead, and embeddability in a wide variety of language runtimes through a C API.

## Versioning semantics

`libddwaf` follows [Semantic Versioning 2.0](https://semver.org/), with a slight twist.

`libddwaf` is a heir to `libsqreen`, the latter which was semantically versioned using `0.y.z`:

> Major version zero (0.y.z) is for initial development. Anything MAY change at any time. The public API SHOULD NOT be considered stable.

To mark the break between `libsqreen` and `libddwaf` (which involved a lot of renaming and changes), it was decided to bump the major version, but some time was needed still to stabilise the public API. Therefore `libddwaf`'s `1.y.z` is operating following semver's usual `0.y.z`, with minor `y` meaning "breaking change" and patch `z` meaning "bugfix".

In addition `libddwaf`'s "unstable" marker on releases means the API may evolve and have breaking changes on minor versions. Nonetheless its codebase and resulting binaries are considered production-ready as the "unstable" marker only applies to `libddwaf`'s public API.

Since `libddwaf` should not be used directly and is wrapped by binding libraries to various languages, any such low-level C API change is handled by Datadog internally and isolated by the higher level binding code, which aims to provide a much stabler high level language-oriented API. In any case, the binding library dependency is directly consumed by the Datadog tracing client libraries, and should there be a breaking change in the binding API it would be handled as gracefully as technically possible within the tracing client library level, and properly handled using the tracing client library dependency verssion constraints so that it picks only compatible versions of the binding library.

## Building

### Quick Start

This project is built using `cmake`.

On Linux and Darwin, the following should produce a static and a dynamic library inside of `build`:

```
mkdir -p build && cd build
cmake ..
make -j4
```

A cross-platform way to achieve the same result (e.g on Windows):

```
cmake -E make_directory build
cd build
cmake ..
cmake --build . --target all -j4
```

And a more involved example, with specific targets, building, then running the test suite along with debug information:

```
cmake -E make_directory build packages
cd build
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_INSTALL_PREFIX=.. -DCPACK_PACKAGE_DIRECTORY=../packages ..
cmake --build . --config RelWithDebInfo --verbose --target libddwaf_shared --target libddwaf_static  --target waf_test -j
cd ../tests
../build/tests/waf_test
```

## Usage

The general process is as follows:

- Load processing rules as a `ddwaf_object` data structure into the WAF engine. This returns a handler.
- Start a context with the returned handler.
- Prepare input to test against the rules into a `ddwaf_object` data structure.
- Perform a run against the input in the context.
- Optionally perform subsequent runs against additional input in the same context. Only newly relevant rules are checked against.
- Discard context and/or handler as needed.

### Example

The full example can be found [here](examples/example.cpp).

```cpp
#include <yaml-cpp/yaml.h>
#include "ddwaf.h"

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

    auto rule = doc.as<ddwaf_object>();//= convert_yaml_to_args(doc);
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
    auto code = ddwaf_run(context, &root, nullptr, &ret, 1000000 /* microseconds */);
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
```

#### YAML to ddwaf::object converter example

```cpp

namespace YAML {

template <>
struct as_if<ddwaf_object, void>
{
    explicit as_if(const Node& node_) : node(node_) {}

    static ddwaf_object yaml_to_object_helper(const Node& node)
    {
        ddwaf_object arg;
        switch (node.Type())
        {
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

    ddwaf_object operator()() const {
        std::list<std::tuple<ddwaf_object&, YAML::Node, YAML::Node::const_iterator>> stack;

        ddwaf_object root = yaml_to_object_helper(node);
        if (root.type == DDWAF_OBJ_MAP || root.type == DDWAF_OBJ_ARRAY) {
            stack.emplace_back(root, node, node.begin());
        }

        while (!stack.empty()) {
            auto current_depth = stack.size();
            auto &[parent_obj, parent_node, it] = stack.back();

            for (;it != parent_node.end(); ++it) {
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

            if (current_depth == stack.size()) { stack.pop_back(); }
        }
        return root;
    }

    const Node& node;
};

} // namespace YAML

```

#### ddwaf::object to YAML converter example

```cpp
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
    std::list<std::tuple<const ddwaf_object&, YAML::Node, std::size_t>> stack;

    YAML::Node root = object_to_yaml_helper(obj);
    if (obj.type == DDWAF_OBJ_MAP || obj.type == DDWAF_OBJ_ARRAY) {
        stack.emplace_back(obj, root, 0);
    }

    while (!stack.empty()) {
        auto current_depth = stack.size();
        auto &[parent_obj, parent_node, index] = stack.back();

        for (;index <parent_obj.nbEntries; ++index) {
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
```

### Example rule

The following rule:
```yaml
version: 2.1
rules:
 - id: crs-042-001
   name: Detect a script tag
   tags:
     category: attack_attempt
     type: xss
   conditions:
    - operator: match_regex
      parameters:
        regex: "^<script>"
        inputs:
         - address: http.server.query
```

applied to the `http.server.query` value `http://localhost/?q=<script>alert() hello world` produces the following result:
```json
[
  {
    "rule": {
      "id": "crs-042-001",
      "name": "Detect a script tag",
      "tags": {
        "category": "attack_attempt",
        "type": "xss"
      }
    },
    "rule_matches": [
      {
        "operator": "match_regex",
        "operator_value": "^<script>",
        "parameters": [
          {
            "address": "http.server.query",
            "key_path": [
              "q"
            ],
            "value": "<script>alert() hello world",
            "highlight": [
              "<script>"
            ]
          }
        ]
      }
    ]
  }
]
```

## Binding implementation notes

See [`BINDING_IMPL_NOTES.md`](./BINDING_IMPL_NOTES.md).
