file(GLOB LIBDDWAF_PERF_SOURCE *.cpp)
file(GLOB LIBDDWAF_PERF_COMMON_SOURCE common/*.cpp)

foreach(PERF ${LIBDDWAF_PERF_SOURCE})
    get_filename_component(PERF_NAME ${PERF} NAME_WLE)

    add_executable(${PERF_NAME} ${PERF} ${LIBDDWAF_PERF_COMMON_SOURCE})
    target_link_libraries(${PERF_NAME} PRIVATE libddwaf_objects lib_yamlcpp lib_rapidjson benchmark)
    target_include_directories(${PERF_NAME} PRIVATE ${LIBDDWAF_PRIVATE_INCLUDES})

    set_target_properties(${PERF_NAME} PROPERTIES
        CXX_STANDARD 20
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS NO)
endforeach()

