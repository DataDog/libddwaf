# Realistic multi-threaded benchmark (see README.md).
#
# Two ways of building it:
#  * as part of the libddwaf tree: `ninja ddwaf_realistic_bench` (opt-in target,
#    linked against libddwaf_static);
#  * standalone, against a libddwaf.a built from any revision (used by ab.py so
#    that both sides of an A/B run use the very same benchmark source):
#      cmake -S benchmark/realistic -B out -DDDWAF_LIB=/path/libddwaf.a \
#            -DDDWAF_INCLUDE_DIR=/path/include
cmake_minimum_required(VERSION 3.14)

set(BENCH_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/traffic.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/node.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/canon.cpp)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(ddwaf_realistic_bench CXX)
    set(CMAKE_CXX_STANDARD 20)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_CXX_EXTENSIONS OFF)
    if(NOT CMAKE_BUILD_TYPE)
        set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
    endif()
    set(DDWAF_LIB "" CACHE FILEPATH "Path to libddwaf.a")
    set(DDWAF_INCLUDE_DIR "" CACHE PATH "Directory containing ddwaf.h")
    if(NOT DDWAF_LIB OR NOT DDWAF_INCLUDE_DIR)
        message(FATAL_ERROR "DDWAF_LIB and DDWAF_INCLUDE_DIR are required in standalone mode")
    endif()
    find_package(Threads REQUIRED)
    add_executable(ddwaf_realistic_bench ${BENCH_SOURCES})
    target_include_directories(ddwaf_realistic_bench PRIVATE ${DDWAF_INCLUDE_DIR})
    target_link_libraries(ddwaf_realistic_bench PRIVATE ${DDWAF_LIB} Threads::Threads)
    if(UNIX AND NOT APPLE)
        target_link_libraries(ddwaf_realistic_bench PRIVATE dl m)
    endif()
else()
    add_executable(ddwaf_realistic_bench EXCLUDE_FROM_ALL ${BENCH_SOURCES})
    target_link_libraries(ddwaf_realistic_bench PRIVATE libddwaf_static)
    target_include_directories(ddwaf_realistic_bench PRIVATE ${libddwaf_SOURCE_DIR}/include)
    find_package(Threads REQUIRED)
    target_link_libraries(ddwaf_realistic_bench PRIVATE Threads::Threads)
endif()

target_compile_definitions(ddwaf_realistic_bench PRIVATE
    BENCH_DEFAULT_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
if(NOT MSVC)
    target_compile_options(ddwaf_realistic_bench PRIVATE -Wall -Wextra)
endif()
