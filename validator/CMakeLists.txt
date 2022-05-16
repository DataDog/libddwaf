set(CMAKE_CXX_STANDARD 17)

file(GLOB_RECURSE LIBDDWAF_VALIDATOR_SOURCE *.cpp)
add_executable(waf_validator ${LIBDDWAF_VALIDATOR_SOURCE})

target_include_directories(waf_validator PRIVATE ${libddwaf_SOURCE_DIR}/include)
target_link_libraries(waf_validator PRIVATE  libddwaf_objects lib_yamlcpp)

add_custom_target(validate
    COMMAND ${CMAKE_BINARY_DIR}/validator/waf_validator
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/validator)

add_dependencies(validate waf_validator)

add_custom_target(test_validator
    COMMAND ${CMAKE_BINARY_DIR}/validator/waf_validator ${CMAKE_SOURCE_DIR}/validator/unit/*
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/validator)


