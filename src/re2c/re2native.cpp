// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <cstdint>
#include <re2/re2.h>

#include <re2c.h>

std::unique_ptr<re2::RE2> current_regex_obj { nullptr };

// Parse and Cache a Regular Expression for later runs
void re2_current_regex_build(const char *regex)
{
    re2::RE2::Options options;
    options.set_max_mem(512 * 1024);
    options.set_log_errors(false);
    options.set_case_sensitive(false);

	std::string_view regex_str = regex;

    if (!regex_str.empty()) {
        re2::StringPiece sp(regex_str.data(), regex_str.size());
        current_regex_obj = std::make_unique<re2::RE2>(sp, options);
	}
}

int re2_current_regex_matches(const char *text, int fromTextIndex, Match* matches, int matchesLength, int timeoutMilliseconds)
{
	std::string_view text_str = text;
	re2::StringPiece allContentSp(text_str.data(), text_str.size());

	// Get the time to measure the timeout
	std::chrono::high_resolution_clock::time_point start;
	if (timeoutMilliseconds > 0) start = std::chrono::high_resolution_clock::now();

	// Find matches until the matches array is full or we run out of text
	re2::StringPiece captures[1];
	int nextMatchIndex = 0;
	while (nextMatchIndex < matchesLength)
	{
		// Find the next match, capturing only the overall match span
		if (!current_regex_obj->Match(allContentSp, fromTextIndex, allContentSp.length(), re2::RE2::UNANCHORED, captures, 1)) break;

		// Identify the match UTF-8 byte offset and length
		int matchOffset = (int)(captures[0].data() - allContentSp.data());
		matches[nextMatchIndex].Index = matchOffset;
		matches[nextMatchIndex].Length = (int)(captures[0].length());
		nextMatchIndex++;

		// Continue search on the character after the match start
		fromTextIndex = matchOffset + 1;

		if (timeoutMilliseconds > 0)
		{
			std::chrono::high_resolution_clock::time_point now = std::chrono::high_resolution_clock::now();
			if (std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count() > timeoutMilliseconds) break;
		}
	}

	// Return the number of matches found
	return nextMatchIndex;
}
