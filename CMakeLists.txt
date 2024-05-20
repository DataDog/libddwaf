cmake_minimum_required(VERSION 3.14)

file(READ "version" version)

string(REGEX REPLACE "-(alpha|beta)[0-9]*$" "" mmp_version ${version})

project(libddwaf VERSION "${mmp_version}")

# Resetting the version allows for alpha and beta suffix releases
set(PROJECT_VERSION ${version})
set(CMAKE_PROJECT_VERSION ${version})

message(STATUS "Project version: ${CMAKE_PROJECT_VERSION}")

if(UNIX AND NOT APPLE)
    set(LINUX TRUE)
endif()

configure_file(src/version.hpp.in ${CMAKE_CURRENT_SOURCE_DIR}/src/version.hpp)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

option(LIBDDWAF_BUILD_SHARED "Build shared library" ON)
option(LIBDDWAF_BUILD_STATIC "Build shared library" ON)
option(LIBDDWAF_TESTING "Load test subdirectories and targets" ON)
option(LIBDDWAF_TEST_COVERAGE "Do coverage if possible" OFF)
option(LIBDDWAF_VECTORIZED_TRANSFORMERS "Enable vectorization for transformers" ON)
option(LIBDDWAF_ENABLE_LTO "Enable link-time optimisation" OFF)

if(NOT MSVC)
    if (APPLE)
        set(CMAKE_OSX_DEPLOYMENT_TARGET "10.12" CACHE STRING "Minimum OS X deployment version")
    endif()

    add_compile_options(-Wall -Wextra -Wno-narrowing)
    if (CMAKE_BUILD_TYPE MATCHES Debug OR CMAKE_BUILD_TYPE MATCHES RelWithDebInfo)
        add_compile_options(-ggdb)
    endif()
else()
    if (CMAKE_BUILD_TYPE MATCHES Debug)
        add_compile_options(/MTd)
    else()
        add_compile_options(/MT)
    endif()

    add_compile_definitions(-D_CRT_SECURE_NO_WARNINGS=1 -Dstrdup=_strdup -Dputenv=_putenv)
endif()

include(GNUInstallDirs)

add_library(glibc_compat_time64 OBJECT ${libddwaf_SOURCE_DIR}/src/glibc-compat/time64.c)
set_target_properties(glibc_compat_time64 PROPERTIES POSITION_INDEPENDENT_CODE 1)

add_library(glibc_compat_math OBJECT ${libddwaf_SOURCE_DIR}/src/glibc-compat/math.c)
set_target_properties(glibc_compat_math PROPERTIES POSITION_INDEPENDENT_CODE 1)

try_compile(STDLIB_MAP_RECURSIVE ${CMAKE_CURRENT_BINARY_DIR}
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/cmake/try_rec_map.cpp
    CXX_STANDARD 20)

# System dependencies
set(LIBDDWAF_INTERFACE_LIBRARIES "")
if(LINUX)
    find_library(LIBPTHREAD pthread)
    find_library(LIBRT rt)
    find_library(LIBDL dl)
    # there is also a call to ceilf that may or may not result in an import.
    # The symbol might live in libm or the normal libc (e.g. musl). In any case,
    # add the dependency
    find_library(LIBM m)

    set(LIBDDWAF_INTERFACE_LIBRARIES
        $<$<BOOL:${LIBPTHREAD}>:pthread>
        $<$<BOOL:${LIBRT}>:rt>
        $<$<BOOL:${LIBDL}>:dl>)
elseif(WIN32)
    list(APPEND LIBDDWAF_INTERFACE_LIBRARIES ws2_32)
endif()

set(LIBDDWAF_PRIVATE_LIBRARIES "")
if(NOT MSVC AND LIBDDWAF_TESTING AND LIBDDWAF_TEST_COVERAGE)
    list(APPEND LIBDDWAF_PRIVATE_LIBRARIES gcov)
endif()

if (LIBDDWAF_ENABLE_LTO)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -flto")
endif()

include(cmake/objects.cmake)

# Static library
if (LIBDDWAF_BUILD_STATIC)
    include(cmake/static.cmake)
endif()

# Shared library
if (LIBDDWAF_BUILD_SHARED)
    include(cmake/shared.cmake)
endif()

include(cmake/package.cmake)

if (LIBDDWAF_TESTING)
    add_subdirectory(third_party EXCLUDE_FROM_ALL)
    add_subdirectory(tests EXCLUDE_FROM_ALL)
    add_subdirectory(validator EXCLUDE_FROM_ALL)
    add_subdirectory(benchmark EXCLUDE_FROM_ALL)
    add_subdirectory(fuzzer EXCLUDE_FROM_ALL)
    add_subdirectory(tools EXCLUDE_FROM_ALL)
    add_subdirectory(examples EXCLUDE_FROM_ALL)
    #add_subdirectory(perf EXCLUDE_FROM_ALL)

    include(cmake/clang-tidy.cmake)
    include(cmake/clang-format.cmake)
endif()
