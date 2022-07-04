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
	
	uint8_t codepoint_to_bytes(uint32_t codepoint, char* utf8_buffer);
	uint8_t write_codepoint(uint32_t codepoint, char* utf8_buffer, uint64_t length_left);
	
	uint32_t fetch_next_codepoint(const char * utf8_buffer, uint64_t& position, uint64_t length);
	
	size_t normalize_codepoint(uint32_t codepoint, int32_t* wb_buffer, size_t wb_buffer_length);
	bool normalize_string(char ** utf8_buffer, uint64_t & buffer_length);

}
