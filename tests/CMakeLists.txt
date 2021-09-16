include(GoogleTest)

file(GLOB_RECURSE LIBDDWAF_TEST_SOURCE *.cpp)
add_executable(testPowerWAF ${LIBDDWAF_SOURCE} ${LIBDDWAF_TEST_SOURCE})

option(LIBDDWAF_TEST_COVERAGE "Do coverage if possible" ON)
set_target_properties(testPowerWAF PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO)

target_include_directories(testPowerWAF PRIVATE ${libddwaf_SOURCE_DIR}/include)
target_include_directories(testPowerWAF PRIVATE ${libddwaf_SOURCE_DIR}/src)
target_include_directories(testPowerWAF PRIVATE ${libddwaf_SOURCE_DIR}/src/rule_processor)
target_compile_definitions(testPowerWAF PRIVATE TESTING=1 SPDLOG_ACTIVE_LEVEL=0)

if(NOT MSVC)
    if(LIBDDWAF_TEST_COVERAGE)
        set_target_properties(testPowerWAF PROPERTIES COMPILE_FLAGS "-O0 -g --coverage")
        if(LIBDDWAF_EXE_LINKER_FLAGS)
            set(COVERAGE_LINK_FLAGS "-lgcov") # --coverage doesn't play nice with nodefaultlibs (wrong lib order)
        else()
            set(COVERAGE_LINK_FLAGS "--coverage")
        endif()
    endif()
else()
  set(COVERAGE_LINK_FLAGS "")

  set_target_properties(testPowerWAF PROPERTIES RUNTIME_OUTPUT_DIRECTORY_DEBUG ".")
  set_target_properties(testPowerWAF PROPERTIES RUNTIME_OUTPUT_DIRECTORY_RELEASE ".")
  set_target_properties(testPowerWAF PROPERTIES RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL ".")
  set_target_properties(testPowerWAF PROPERTIES RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO ".")
endif()

target_link_libraries(testPowerWAF
    PRIVATE lib_gtest ${COVERAGE_LINK_FLAGS}
    ${LIBDDWAF_PRIVATE_LIBRARIES} ${LIBDDWAF_INTERFACE_LIBRARIES}
    ${LIBDDWAF_EXE_LINKER_FLAGS} lib_yamlcpp)

gtest_discover_tests(testPowerWAF WORKING_DIRECTORY ${libddwaf_SOURCE_DIR}/tests)
