// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

#pragma once

namespace ddwaf::utf8
{
#define UTF8_MAX_CODEPOINT 0x10FFFF
#define UTF8_INVALID 0xFFFFFFFF
#define UTF8_EOF 0xFFFFFFFE
	
	uint8_t codepointToBytes(uint32_t codepoint, char* utf8Buffer);
	uint8_t writeCodePoint(uint32_t codepoint, char* utf8Buffer, uint64_t lengthLeft);
	
	uint32_t fetchNextCodepoint(const char * utf8_buffer, uint64_t& position, uint64_t length);
	
	size_t normalizeCodepoint(uint32_t codepoint, int32_t* wbBuffer, size_t wbBufferLength);
	bool normalizeString(char ** utf8Buffer, uint64_t & bufferLength);

}
