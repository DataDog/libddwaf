find_package(benchmark REQUIRED)

add_executable(bench_trie bench_trie.cpp)
target_link_libraries(bench_trie PRIVATE benchmark::benchmark)
