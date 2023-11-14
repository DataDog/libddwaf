file(GLOB_RECURSE LIBDDWAF_FUZZER_SOURCE src/*.cpp)
add_executable(fuzzer ${LIBDDWAF_SOURCE} ${LIBDDWAF_FUZZER_SOURCE})

set_target_properties(fuzzer PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO)

target_include_directories(fuzzer PRIVATE ${libddwaf_SOURCE_DIR}/fuzzing/tools)
target_include_directories(fuzzer PRIVATE ${LIBDDWAF_PUBLIC_INCLUDES} ${LIBDDWAF_PRIVATE_INCLUDES})

set_target_properties(fuzzer PROPERTIES COMPILE_FLAGS "-fsanitize=fuzzer,address,undefined,leak -fprofile-instr-generate -fcoverage-mapping")
set_target_properties(fuzzer PROPERTIES LINK_FLAGS "-fsanitize=fuzzer,address,undefined,leak -fprofile-instr-generate -fcoverage-mapping")

target_link_libraries(fuzzer PRIVATE
    ${LIBDDWAF_PRIVATE_LIBRARIES} ${LIBDDWAF_INTERFACE_LIBRARIES} lib_yamlcpp)


