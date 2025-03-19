file(GLOB_RECURSE LIBDDWAF_BENCHMARK_SOURCE *.cpp)

add_executable(waf_benchmark ${LIBDDWAF_BENCHMARK_SOURCE})
target_compile_options(waf_benchmark PRIVATE $<$<BOOL:${LIBDDWAF_ENABLE_LTO}>:-flto>)
target_link_libraries(waf_benchmark PRIVATE libddwaf_objects lib_yamlcpp lib_rapidjson m)
target_include_directories(waf_benchmark PRIVATE ${libddwaf_SOURCE_DIR}/src)

if (LIBDDWAF_BENCHMARK_PGO_STAGE1)
    set_target_properties(waf_benchmark PROPERTIES
        COMPILE_FLAGS -fprofile-instr-generate
        LINK_FLAGS -fprofile-instr-generate)
else()
    if (LIBDDWAF_BENCHMARK_PGO_STAGE2_PROFILE)
        target_compile_options(waf_benchmark PRIVATE -fprofile-use=${LIBDDWAF_BENCHMARK_PGO_STAGE2_PROFILE})
        if (LIBDDWAF_BENCHMARK_BOLT_STAGE3)
            # Relocations are only required for BOLT
            target_link_options(waf_benchmark PRIVATE -Wl,-q)
        endif()
    endif()

    add_custom_target(run_benchmark
        COMMAND $<TARGET_FILE:waf_benchmark>
        --scenarios=${CMAKE_CURRENT_SOURCE_DIR}/scenarios
        --iterations=1000
        --format=json
        --output=benchmark_results.json
        --fixtures="random"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )
    add_dependencies(run_benchmark waf_benchmark)
endif()
