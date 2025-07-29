// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <cstdint>
#include "../common/afl_wrapper.hpp"
#include "../common/utils.hpp"
#include "condition/sqli_detector.hpp"
#include "tokenizer/sql_base.hpp"

using namespace ddwaf;
using namespace ddwaf_afl;
using namespace std::literals;

// Global dialect setting
ddwaf::sql_dialect dialect = ddwaf::sql_dialect::generic;

template <typename... Args> 
std::vector<condition_parameter> gen_param_def(Args... addresses) {
    return {{{{std::string{addresses}, get_target_index(addresses)}}}...};
}

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv) {
    ddwaf::memory::set_local_memory_resource(std::pmr::new_delete_resource());

    for (int i = 0; i < *argc; i++) {
        std::string_view arg = (*argv)[i];
        if (arg.starts_with("--dialect=")) {
            dialect = ddwaf::sql_dialect_from_type(arg.substr(sizeof("--dialect=") - 1));
            break;
        }
    }
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    sqli_detector cond{
        {gen_param_def("server.db.statement", "server.request.query", "server.db.statement")}
    };

    InputSplitter splitter(data, size);
    auto resource = splitter.get_string();
    auto param = splitter.get_remaining();

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    
    // add database statement
    ddwaf_object_map_add(
        &root, 
        "server.db.statement", 
        ddwaf_object_stringl(&tmp, resource.data(), resource.size())
    );
    
    // add request query parameter
    ddwaf_object_map_add(
        &root, 
        "server.request.query", 
        ddwaf_object_stringl(&tmp, param.data(), param.size())
    );
    
    // add database system info
    auto dialect_str = ddwaf::sql_dialect_to_string(dialect);
    ddwaf_object_map_add(
        &root, 
        "server.db.system",
        ddwaf_object_stringl(&tmp, dialect_str.data(), dialect_str.size())
    );
    
    // create object store and evaluate condition
    object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto result = cond.eval(cache, store, {}, {}, {}, deadline);
    
    prevent_optimization(result);
    
    return 0;
}

// Create AFL++ main function with initialization
AFL_FUZZ_TARGET_WITH_INIT("sqli_detector_fuzz", LLVMFuzzerTestOneInput, LLVMFuzzerInitialize) 