#include <experimental/memory_resource>

static_assert(sizeof(std::experimental::pmr::monotonic_buffer_resource::monotonic_buffer_resource) > 0);
int main() { return 0; }
