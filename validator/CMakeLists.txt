file(GLOB_RECURSE LIBDDWAF_VALIDATOR_SOURCE *.cpp)
add_executable(waf_validator ${LIBDDWAF_VALIDATOR_SOURCE})

set_target_properties(waf_validator PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO)

target_include_directories(waf_validator PRIVATE ${libddwaf_SOURCE_DIR}/include)
target_link_libraries(waf_validator PRIVATE  libddwaf_objects lib_yamlcpp)

add_custom_target(validate
    COMMAND ${CMAKE_BINARY_DIR}/validator/waf_validator
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/validator)
add_dependencies(validate waf_validator)

add_custom_target(test_validator
    COMMAND ${CMAKE_BINARY_DIR}/validator/waf_validator --tests ${CMAKE_SOURCE_DIR}/validator/self-tests/
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/validator)
add_dependencies(test_validator waf_validator)

add_custom_target(validate_valgrind
    COMMAND valgrind --leak-check=full --show-reachable=yes --suppressions=${CMAKE_SOURCE_DIR}/tests/re2.supp  ${CMAKE_BINARY_DIR}/validator/waf_validator
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/validator)
add_dependencies(validate_valgrind waf_validator)

