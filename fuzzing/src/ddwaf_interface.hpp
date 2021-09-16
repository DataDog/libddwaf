// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#ifndef DDWAF_FUZZER_UTILS_H
#define DDWAF_FUZZER_UTILS_H

#include <cstdlib>
#include <ddwaf.h>

ddwaf_handle init_waf();
void run_waf(ddwaf_handle handle, ddwaf_object args, size_t timeLeftInUs);

#endif
