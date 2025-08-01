// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <cstdint>
#include <vector>
#include "../common/afl_wrapper.hpp"
#include "../common/utils.hpp"
#include "condition/cmdi_detector.hpp"

using namespace ddwaf;
using namespace ddwaf_afl;
using namespace std::literals;

template <typename... Args> 
std::vector<condition_parameter> gen_param_def(Args... addresses) {
    return {{{{std::string{addresses}, get_target_index(addresses)}}}...};
}

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv) {
    // Set up memory resource
    ddwaf::memory::set_local_memory_resource(std::pmr::new_delete_resource());
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Create command injection detector
    cmdi_detector cond{{gen_param_def("server.sys.exec.cmd", "server.request.query")}};
    
    // Use input splitter to parse array elements and param
    InputSplitter splitter(data, size);
    
    // Parse number of array elements
    auto num_elements = splitter.get<uint8_t>() % 10 + 1; // 1-10 elements
    
    // Parse array elements
    std::vector<std::string_view> resource_array;
    for (size_t i = 0; i < num_elements; ++i) {
        if (!splitter.has_data()) break;
        auto element = splitter.get_string();
        if (!element.empty()) {
            resource_array.push_back(element);
        }
    }
    
    // Get the parameter from remaining data
    auto param = splitter.get_remaining();
    
    // Create ddwaf objects
    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object array;
    ddwaf_object_map(&root);
    
    // Create array for command execution
    ddwaf_object_array(&array);
    for (auto arg : resource_array) {
        ddwaf_object_array_add(&array, ddwaf_object_stringl(&tmp, arg.data(), arg.size()));
    }
    
    // Add command execution array
    ddwaf_object_map_add(&root, "server.sys.exec.cmd", &array);
    
    // Add request query parameter
    ddwaf_object_map_add(
        &root, 
        "server.request.query", 
        ddwaf_object_stringl(&tmp, param.data(), param.size())
    );
    
    // Create object store and evaluate condition
    object_store store;
    store.insert(root);
    
    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto result = cond.eval(cache, store, {}, {}, {}, deadline);
    
    // Prevent compiler optimization
    prevent_optimization(result);
    
    return 0;
}

// Create AFL++ main function with initialization
AFL_FUZZ_TARGET_WITH_INIT("cmdi_detector_fuzz", LLVMFuzzerTestOneInput, LLVMFuzzerInitialize) 