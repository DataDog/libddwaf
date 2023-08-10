cmake_minimum_required(VERSION 3.13)
project(smoketest C)
set(CMAKE_C_STANDARD 11)

option(LINK_DDWAF_STATIC "Link against static libddwaf" OFF)

set(SOURCE_FILES smoke.c)

find_package(libddwaf REQUIRED)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_executable(smoketest ${SOURCE_FILES})

if(LINK_DDWAF_STATIC)
    target_link_libraries(smoketest PRIVATE libddwaf_static -Wl,--push-state -Wl,-L${LIBDDWAF_SMOKETEST_SYSROOT} -l:libc++.a -l:libc++experimental.a -l:libc++abi.a -l:libunwind.a -Wl,--pop-state)
else()
    target_link_libraries(smoketest PRIVATE libddwaf_shared)
endif()
