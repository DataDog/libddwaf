#include <experimental/memory_resource>

static_assert(sizeof(std::experimental::pmr::polymorphic_allocator<char>) > 0);
int main() { return 0; }
