#include <memory_resource>

static_assert(sizeof(std::pmr::monotonic_buffer_resource) > 0);
int main() { return 0; }
