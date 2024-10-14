#include<unordered_map>

struct X {
	std::unordered_map<int, X> x{};
};
static X x{};

int main() {}
