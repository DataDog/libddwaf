#include <memory_resource>
#include <version>

#if !defined(__cpp_lib_memory_resource)
#  error "No memory resource available"
#endif

int main() {}
