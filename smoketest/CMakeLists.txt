cmake_minimum_required(VERSION 3.13)
project(smoketest C)
set(CMAKE_C_STANDARD 11)

option(LIBDDWAF_SMOKE_LINK_STATIC "Link against static libddwaf" OFF)

set(SOURCE_FILES smoke.c)

find_package(libddwaf REQUIRED)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_executable(smoketest ${SOURCE_FILES})

if(LIBDDWAF_SMOKE_LINK_STATIC)
    target_link_libraries(smoketest PRIVATE libddwaf_static ${LIBDDWAF_SMOKE_LINK_STATIC_FLAGS})
else()
    target_link_libraries(smoketest PRIVATE libddwaf_shared)
endif()
