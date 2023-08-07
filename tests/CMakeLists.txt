include(GoogleTest)

file(GLOB_RECURSE LIBDDWAF_TEST_SOURCE *.cpp)
add_executable(testPowerWAF ${LIBDDWAF_TEST_SOURCE})

set_target_properties(testPowerWAF PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO)

target_include_directories(testPowerWAF PRIVATE ${libddwaf_SOURCE_DIR}/include)
target_include_directories(testPowerWAF PRIVATE ${libddwaf_SOURCE_DIR}/src)
if(NOT STDLIB_MAP_RECURSIVE)
    target_compile_definitions(testPowerWAF PRIVATE HAS_NONRECURSIVE_UNORDERED_MAP)
endif()

set(LIBDDWAF_TEST_LIBRARIES lib_gtest libddwaf_objects lib_yamlcpp lib_rapidjson)
if(NOT MSVC AND LIBDDWAF_TEST_COVERAGE)
    target_compile_options(testPowerWAF PRIVATE -ggdb --coverage)
    list(APPEND LIBDDWAF_TEST_LIBRARIES gcov)
endif()

target_link_libraries(testPowerWAF
    PRIVATE ${LIBDDWAF_PRIVATE_LIBRARIES} ${LIBDDWAF_INTERFACE_LIBRARIES}
           ${LIBDDWAF_EXE_LINKER_FLAGS} ${LIBDDWAF_TEST_LIBRARIES})

add_custom_target(test
    COMMAND ${CMAKE_BINARY_DIR}/tests/testPowerWAF
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests)
add_dependencies(test testPowerWAF)

add_custom_target(test_valgrind
    COMMAND valgrind --leak-check=full --show-reachable=yes --suppressions=re2.supp  ${CMAKE_BINARY_DIR}/tests/testPowerWAF
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests)
add_dependencies(test_valgrind testPowerWAF)


