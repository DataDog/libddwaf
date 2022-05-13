set(CMAKE_CXX_STANDARD 17)

file(GLOB_RECURSE LIBDDWAF_VALIDATOR_SOURCE *.cpp)
add_executable(validate_waf ${LIBDDWAF_VALIDATOR_SOURCE})

target_include_directories(validate_waf PRIVATE ${libddwaf_SOURCE_DIR}/include)

target_link_libraries(validate_waf PRIVATE  libddwaf_objects lib_yamlcpp)
