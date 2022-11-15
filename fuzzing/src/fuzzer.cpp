// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ddwaf.h>

#include "ddwaf_interface.hpp"
#include "ddwaf_object_builder.hpp"
#include "helpers.hpp"

bool verbose = false;
bool fuzzTimeout = false;

ddwaf_handle handle = NULL;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    for (int i = 0; i < *argc; i++) {
        if (strcmp((*argv)[i], "--V") == 0) {
            verbose = true;
        } else if (strcmp((*argv)[i], "--fuzz_timeout") == 0) {
            fuzzTimeout = true;
        }
    }

    handle = init_waf();

    if (handle == NULL) {
        __builtin_trap();
    }

    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *bytes, size_t size)
{
    size_t timeLeftInUs;
    ddwaf_object args = build_object(bytes, size, verbose, fuzzTimeout, &timeLeftInUs);
    run_waf(handle, args, timeLeftInUs);
    return 0;
}
