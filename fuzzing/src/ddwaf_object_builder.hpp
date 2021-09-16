// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#ifndef DDWAF_FUZZER_OBJECT_BUILDER_H
#define DDWAF_FUZZER_OBJECT_BUILDER_H

#include <cstdlib>
#include <ddwaf.h>

ddwaf_object build_object(const uint8_t* bytes, size_t size, bool verbose, bool fuzzTimeout, size_t* timeLeftInMs);

#endif
