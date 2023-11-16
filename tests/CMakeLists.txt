include(GoogleTest)

file(GLOB_RECURSE LIBDDWAF_TEST_SOURCE *.cpp)
add_executable(waf_test ${LIBDDWAF_TEST_SOURCE})

set_target_properties(waf_test PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO)

target_include_directories(waf_test PRIVATE ${LIBDDWAF_PUBLIC_INCLUDES} ${LIBDDWAF_PRIVATE_INCLUDES})

if(NOT STDLIB_MAP_RECURSIVE)
    target_compile_definitions(waf_test PRIVATE HAS_NONRECURSIVE_UNORDERED_MAP)
endif()

if (LIBDDWAF_VECTORIZED_TRANSFORMERS)
    target_compile_definitions(waf_test PRIVATE LIBDDWAF_VECTORIZED_TRANSFORMERS)
endif()

set(LIBDDWAF_TEST_LIBRARIES lib_gtest lib_gmock libddwaf_objects lib_yamlcpp lib_rapidjson)
if(NOT MSVC AND LIBDDWAF_TEST_COVERAGE)
    target_compile_options(waf_test PRIVATE -ggdb --coverage)
    list(APPEND LIBDDWAF_TEST_LIBRARIES gcov)
else()
  set_target_properties(waf_test PROPERTIES RUNTIME_OUTPUT_DIRECTORY_DEBUG ".")
  set_target_properties(waf_test PROPERTIES RUNTIME_OUTPUT_DIRECTORY_RELEASE ".")
  set_target_properties(waf_test PROPERTIES RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL ".")
  set_target_properties(waf_test PROPERTIES RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO ".")
endif()

target_link_options(waf_test PRIVATE ${LIBDDWAF_EXE_LINKER_FLAGS})
target_link_libraries(waf_test PRIVATE ${LIBDDWAF_PRIVATE_LIBRARIES}
    ${LIBDDWAF_INTERFACE_LIBRARIES} ${LIBDDWAF_TEST_LIBRARIES})

add_custom_target(test
    COMMAND ${CMAKE_BINARY_DIR}/tests/waf_test
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests)
add_dependencies(test waf_test)

add_custom_target(test_valgrind
    COMMAND valgrind --leak-check=full --show-reachable=yes --suppressions=re2.supp  ${CMAKE_BINARY_DIR}/tests/waf_test --gtest_filter=-TestTimer.*
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests)
add_dependencies(test_valgrind waf_test)


