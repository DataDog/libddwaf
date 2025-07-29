// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include "../common/afl_wrapper.hpp"
#include "../common/utils.hpp"
#include "condition/lfi_detector.hpp"
#include <cstdint>

using namespace ddwaf;
using namespace ddwaf_afl;
using namespace std::literals;

template <typename... Args> std::vector<condition_parameter> gen_param_def(Args... addresses)
{
    return {{{{std::string{addresses}, get_target_index(addresses)}}}...};
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    // Set up memory resource
    ddwaf::memory::set_local_memory_resource(std::pmr::new_delete_resource());
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Create local file inclusion detector
    lfi_detector cond{{gen_param_def("server.io.fs.file", "server.request.query")}};

    // Use input splitter to parse resource and param
    InputSplitter splitter(data, size);
    auto resource = splitter.get_string();
    auto param = splitter.get_remaining();

    // Create ddwaf objects
    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);

    // Add filesystem file path
    ddwaf_object_map_add(
        &root, "server.io.fs.file", ddwaf_object_stringl(&tmp, resource.data(), resource.size()));

    // Add request query parameter
    ddwaf_object_map_add(
        &root, "server.request.query", ddwaf_object_stringl(&tmp, param.data(), param.size()));

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
AFL_FUZZ_TARGET_WITH_INIT("lfi_detector_fuzz", LLVMFuzzerTestOneInput, LLVMFuzzerInitialize)