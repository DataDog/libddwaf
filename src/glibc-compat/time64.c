// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2023 Datadog, Inc.

#if defined(__linux__) && !defined(__GLIBC__) && (defined(__arm__) || defined(__i386__))

#include <stdlib.h>
#include <features.h>

void *dlsym(void * handle, const char *name);

// use weak attribute so that on static builds there is no indirection
__attribute__((weak))
void *__dlsym_time64(void *handle, const char *name) {
    // no problem calling the plain dlsym as we don't use the function for which
    // it would make a difference
    return dlsym(handle, name);
}

#endif
