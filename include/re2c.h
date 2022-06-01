
struct Match {
	uint32_t Index;
	uint32_t Length;
};

void re2_current_regex_build(const char *regex);
int re2_current_regex_matches(const char *text, int fromTextIndex, Match* matches, int matchesLength, int timeoutMilliseconds);
