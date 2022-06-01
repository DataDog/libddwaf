
struct Match {
	__int32 Index;
	__int32 Length;
};

void re2_current_regex_build(const char *regex);
int re2_current_regex_matches(const char *text, int fromTextIndex, Match* matches, int matchesLength, int timeoutMilliseconds);
