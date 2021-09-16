// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#ifndef DDWAF_FUZZER_HELPERS_H
#define DDWAF_FUZZER_HELPERS_H

#include <ddwaf.h>

void print_object(ddwaf_object object);
char* read_file_content(const char* filename, size_t* size);

#endif
