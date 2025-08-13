// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <unistd.h>
#include <vector>

// Standard includes for reading input
#include <signal.h>

#define AFL_LOOP_ITERATIONS 1000

namespace ddwaf_afl {

// Type alias for LLVMFuzzOneInput function
using FuzzFunction = std::function<int(const uint8_t *, size_t)>;
using InitFunction = std::function<int(int *, char ***)>;

// Standalone mode helper
int run_standalone(const char *name, FuzzFunction fuzz_func, int argc, char **argv)
{
    // Standalone mode - read from file or stdin for testing
    std::vector<uint8_t> data;

    if (argc > 1) {
        // Read from file
        std::ifstream file(argv[1], std::ios::binary);
        if (!file) {
            std::cerr << "Failed to open file: " << argv[1] << std::endl;
            return 1;
        }

        file.seekg(0, std::ios::end);
        size_t size = file.tellg();
        file.seekg(0, std::ios::beg);

        data.resize(size);
        file.read(reinterpret_cast<char *>(data.data()), size);
    } else {
        // Read from stdin
        char buffer[4096];
        while (std::cin.read(buffer, sizeof(buffer)) || std::cin.gcount() > 0) {
            size_t bytes_read = std::cin.gcount();
            data.insert(data.end(), buffer, buffer + bytes_read);
        }
    }

    if (data.empty()) {
        std::cerr << "No input data provided" << std::endl;
        return 1;
    }

    std::cout << "Running " << name << " with " << data.size() << " bytes of input" << std::endl;
    int result = fuzz_func(data.data(), data.size());
    std::cout << "Fuzzer returned: " << result << std::endl;
    return result;
}

// AFL++ mode helper - this will be called from main with proper persistent mode
int run_afl_iteration(FuzzFunction fuzz_func)
{
    static uint8_t input_buffer[1024 * 1024]; // 1MB buffer

    // Read input for this iteration
    ssize_t len = read(STDIN_FILENO, input_buffer, sizeof(input_buffer));

    if (len <= 0) {
        return 0; // No input available
    }

    // Call the actual fuzzing function
    // Any crashes or hangs will be caught by AFL++
    fuzz_func(input_buffer, static_cast<size_t>(len));

    return 1; // Success
}

} // namespace ddwaf_afl

// Main macro that implements the correct AFL++ persistent mode pattern
#define AFL_FUZZ_TARGET(name, fuzz_func)                                                           \
    int main(int argc, char **argv)                                                                \
    {                                                                                              \
        /* Handle command line arguments for standalone mode */                                    \
        if (argc > 1) {                                                                            \
            return ddwaf_afl::run_standalone(name, fuzz_func, argc, argv);                         \
        }                                                                                          \
                                                                                                   \
        /* AFL++ persistent mode loop - must be in main function */                                \
        /* This runs up to AFL_LOOP_ITERATIONS iterations per process for better performance */    \
        while (__AFL_LOOP(AFL_LOOP_ITERATIONS)) {                                                  \
            if (!ddwaf_afl::run_afl_iteration(fuzz_func)) {                                        \
                break;                                                                             \
            }                                                                                      \
        }                                                                                          \
                                                                                                   \
        return 0;                                                                                  \
    }

#define AFL_FUZZ_TARGET_WITH_INIT(name, fuzz_func, init_func)                                      \
    int main(int argc, char **argv)                                                                \
    {                                                                                              \
        /* Handle initialization if provided */                                                    \
        if (init_func) {                                                                           \
            int result = init_func(&argc, &argv);                                                  \
            if (result != 0) {                                                                     \
                std::cerr << "Initialization failed with code: " << result << std::endl;           \
                return result;                                                                     \
            }                                                                                      \
        }                                                                                          \
                                                                                                   \
        /* Handle command line arguments for standalone mode */                                    \
        if (argc > 1) {                                                                            \
            return ddwaf_afl::run_standalone(name, fuzz_func, argc, argv);                         \
        }                                                                                          \
                                                                                                   \
        /* AFL++ persistent mode loop - must be in main function */                                \
        /* This runs up to AFL_LOOP_ITERATIONS iterations per process for better performance */    \
        while (__AFL_LOOP(AFL_LOOP_ITERATIONS)) {                                                  \
            if (!ddwaf_afl::run_afl_iteration(fuzz_func)) {                                        \
                break;                                                                             \
            }                                                                                      \
        }                                                                                          \
                                                                                                   \
        return 0;                                                                                  \
    }

// Convenience macros for common patterns
#define AFL_SIMPLE_TARGET(name, header, func_call)                                                 \
    extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)                        \
    {                                                                                              \
        func_call;                                                                                 \
        return 0;                                                                                  \
    }                                                                                              \
    AFL_FUZZ_TARGET(name, LLVMFuzzerTestOneInput)

// For targets that need custom initialization
#define AFL_INIT_TARGET(name, header, init_code, func_call)                                        \
    extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)                                   \
    {                                                                                              \
        init_code;                                                                                 \
        return 0;                                                                                  \
    }                                                                                              \
    extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)                        \
    {                                                                                              \
        func_call;                                                                                 \
        return 0;                                                                                  \
    }                                                                                              \
    AFL_FUZZ_TARGET_WITH_INIT(name, LLVMFuzzerTestOneInput, LLVMFuzzerInitialize)