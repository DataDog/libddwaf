// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "utils.hpp"
#include <memory>
#include <string>
#include <vector>

#include "generator/base.hpp"
#include <condition.hpp>
#include <object_store.hpp>

namespace ddwaf {

/*
{
  "preprocessors": [
    {
      "id": "preprocessor-001",
      "generator": "extract_schema",
      "conditions": [
        {
          "operator": "equals",
          "parameters": {
            "inputs": [
              {
                "address": "waf.context.settings",
                "key_path": [
                  "generate-schema"
                ]
              }
            ],
            "type": "boolean",
            "value": true
          }
        }
      ],
      "parameters": {
        "mappings": [
          {
            "input": {
              "address": "server.request.body"
            },
            "output": "server.request.body.schema"
          },
          {
            "input": {
              "address": "server.request.headers.no_cookies"
            },
            "output": "server.request.headers.no_cookies.schema"
          }
        ],
        "scanners": [
          "ecd38ebc-930d-499e-b4aa-c1f6606386f4"
        ]
      },
      "evaluate": false,
      "output": true
    }
  ]
}
*/
class preprocessor {
public:
    using ptr = std::shared_ptr<preprocessor>;
    struct target_mapping {
        // TODO implement n:1 support
        target_index input;
        target_index output;
        std::string output_address;
    };

    struct cache_type {
        bool result{false};
        std::optional<std::vector<condition::ptr>::const_iterator> last_cond{};
    };

    preprocessor(std::string id, std::unique_ptr<generator::base> generator,
        std::vector<condition::ptr> conditions, std::vector<target_mapping> mappings, bool evaluate,
        bool output)
        : id_(std::move(id)), generator_(std::move(generator)), conditions_(std::move(conditions)),
          mappings_(std::move(mappings)), evaluate_(evaluate), output_(output)
    {}

    preprocessor(const preprocessor &) = delete;
    preprocessor &operator=(const preprocessor &) = delete;

    preprocessor(preprocessor &&rhs) noexcept = default;
    preprocessor &operator=(preprocessor &&rhs) noexcept = default;
    ~preprocessor() = default;

    void eval(object_store &store, optional_ref<ddwaf_object> &derived, cache_type &cache,
        ddwaf::timer &deadline) const;

protected:
    std::string id_;
    std::unique_ptr<generator::base> generator_;
    std::vector<condition::ptr> conditions_;
    std::vector<target_mapping> mappings_;
    bool evaluate_{false};
    bool output_{true};
};

} // namespace ddwaf
