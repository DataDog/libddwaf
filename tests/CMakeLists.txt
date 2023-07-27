include(GoogleTest)

file(GLOB_RECURSE LIBDDWAF_TEST_SOURCE *.cpp)
add_executable(testPowerWAF ${LIBDDWAF_SOURCE} ${LIBDDWAF_TEST_SOURCE})

option(LIBDDWAF_TEST_COVERAGE "Do coverage if possible" OFF)

set_target_properties(testPowerWAF PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO)

target_include_directories(testPowerWAF PRIVATE ${libddwaf_SOURCE_DIR}/include)
target_include_directories(testPowerWAF PRIVATE ${libddwaf_SOURCE_DIR}/src)
target_include_directories(testPowerWAF PRIVATE ${libddwaf_SOURCE_DIR}/src/rule_processor)
if(NOT STDLIB_MAP_RECURSIVE)
    target_compile_definitions(testPowerWAF PRIVATE HAS_NONRECURSIVE_UNORDERED_MAP)
endif()

set(COVERAGE_LINK_FLAGS "")
if(NOT MSVC)
    if(LIBDDWAF_TEST_COVERAGE)
        set_target_properties(testPowerWAF PROPERTIES COMPILE_FLAGS "-ggdb --coverage")
        set(COVERAGE_LINK_FLAGS "-lgcov --coverage")
    else()
        set_target_properties(testPowerWAF PROPERTIES COMPILE_FLAGS "-ggdb")
    endif()
else()
  set_target_properties(testPowerWAF PROPERTIES RUNTIME_OUTPUT_DIRECTORY_DEBUG ".")
  set_target_properties(testPowerWAF PROPERTIES RUNTIME_OUTPUT_DIRECTORY_RELEASE ".")
  set_target_properties(testPowerWAF PROPERTIES RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL ".")
  set_target_properties(testPowerWAF PROPERTIES RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO ".")
endif()

target_link_libraries(testPowerWAF
    PRIVATE lib_gtest ${COVERAGE_LINK_FLAGS}
    ${LIBDDWAF_PRIVATE_LIBRARIES} ${LIBDDWAF_INTERFACE_LIBRARIES}
    ${LIBDDWAF_EXE_LINKER_FLAGS} lib_yamlcpp lib_rapidjson)

add_custom_target(test
    COMMAND ${CMAKE_BINARY_DIR}/tests/testPowerWAF
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests)
add_dependencies(test testPowerWAF)

add_custom_target(test_valgrind
    COMMAND valgrind --leak-check=full --show-reachable=yes --suppressions=re2.supp  ${CMAKE_BINARY_DIR}/tests/testPowerWAF
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests)
add_dependencies(test_valgrind testPowerWAF)


