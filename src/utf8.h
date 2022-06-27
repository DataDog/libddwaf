// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#ifndef utf8_h
#define utf8_h

uint8_t codepointToUTF8(uint32_t codepoint, char* utf8_buffer);
uint8_t writeCodePoint(uint32_t codepoint, char* utf8_buffer, uint64_t lengthLeft);

#endif /* utf8_h */
