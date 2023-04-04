``
## Usage

The general process is as follows:

- Load processing rules as a `ddwaf_object` data structure into the WAF engine. This returns a handler.
- Start a context with the returned handler.
- Prepare input to test against the rules into a `ddwaf_object` data structure.
- Perform a run against the input in the context.
- Optionally perform subsequent runs against additional input in the same context. Only newly relevant rules are checked against.
- Discard context and/or handler as needed.

### Example

```c
#include <yaml-cpp/yaml.h>
#include "ddwaf.h"

int main(void)
{

    YAML::Node doc = YAML::Load(R"({version: '0.1', events: [{id: 1, tags: {type: flow1}, conditions: [{operation: match_regex, parameters: {inputs: [arg1], regex: .*}},{operation: match_regex, parameters: {inputs: [arg2], regex: .*}}], action: record}]})");

    ddwaf_object rule = doc.as<ddwaf_object>();//= convert_yaml_to_args(doc);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ddwaf_object_free(&rule);
    if (handle == nullptr) {
        exit(EXIT_FAILURE);
    }

    ddwaf_context context = ddwaf_context_init(handle);
    if (handle == nullptr) {
        ddwaf_destroy(handle);
        exit(EXIT_FAILURE);
    }

    ddwaf_object param1, param2, tmp;
    ddwaf_object_map(&param1);
    ddwaf_object_map(&param2);
    ddwaf_object_map_add(&param1, "arg1", ddwaf_object_string(&tmp, "string 1"));
    ddwaf_object_map_add(&param2, "arg2", ddwaf_object_string(&tmp, "string 2"));

    ddwaf_result ret;
    auto code = ddwaf_run(context, &param1, nullptr, &ret, LONG_TIME);
    printf("Output first run: %d\n", code);
    ddwaf_result_free(&ret);

    code = ddwaf_run(context, &param2, nullptr, &ret, LONG_TIME);
    printf("Output second run: %d - %s\n", ret.action, ret.data);
    ddwaf_result_free(&ret);

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}
```

### YAML to ddwaf::object converter example

```cpp
namespace YAML
{

class parsing_error : public std::exception
{
public:
    parsing_error(const std::string& what) : what_(what) {}
    const char* what() { return what_.c_str(); }

protected:
    const std::string what_;
};

ddwaf_object node_to_arg(const Node& node)
{
    switch (node.Type())
    {
        case NodeType::Sequence:
        {
            ddwaf_object arg;
            ddwaf_object_array(&arg);
            for (auto it = node.begin(); it != node.end(); ++it)
            {
                ddwaf_object child = node_to_arg(*it);
                ddwaf_object_array_add(&arg, &child);
            }
            return arg;
        }
        case NodeType::Map:
        {
            ddwaf_object arg;
            ddwaf_object_map(&arg);
            for (auto it = node.begin(); it != node.end(); ++it)
            {
                std::string key    = it->first.as<std::string>();
                ddwaf_object child = node_to_arg(it->second);
                ddwaf_object_map_addl(&arg, key.c_str(), key.size(), &child);
            }
            return arg;
        }
        case NodeType::Scalar:
        {
            const std::string& value = node.Scalar();
            ddwaf_object arg;
            ddwaf_object_stringl(&arg, value.c_str(), value.size());
            return arg;
        }
        case NodeType::Null:
        case NodeType::Undefined:
            // Perhaps this should return an invalid pwarg
            ddwaf_object arg;
            ddwaf_object_invalid(&arg);
            return arg;
    }

    throw parsing_error("Invalid YAML node type");
}

template <>
struct as_if<ddwaf_object, void> {
    explicit as_if(const Node& node_) : node(node_) {}
    ddwaf_object operator()() const { return node_to_arg(node); }
    const Node& node;
};

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
