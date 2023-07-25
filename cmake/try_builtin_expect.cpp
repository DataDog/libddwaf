#include <iostream>

#define LIKELY(condition) __builtin_expect(!!(condition), 1)

int main() {
    bool condition = true;
    if (LIKELY(condition)) {
        std::cout << "Hello Worlds\n";
    }
    return 0;
}
