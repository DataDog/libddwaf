file(GLOB LIBDDWAF_EXAMPLE_SOURCE *.cpp)

foreach(EXAMPLE ${LIBDDWAF_EXAMPLE_SOURCE})
    get_filename_component(EXAMPLE_NAME ${EXAMPLE} NAME_WLE)

    add_executable(${EXAMPLE_NAME} ${EXAMPLE})
    target_link_libraries(${EXAMPLE_NAME} PRIVATE libddwaf_objects lib_yamlcpp lib_rapidjson)
    target_include_directories(${EXAMPLE_NAME} PRIVATE ${LIBDDWAF_PRIVATE_INCLUDES})

    set_target_properties(${EXAMPLE_NAME} PROPERTIES
        CXX_STANDARD 20
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS NO)
endforeach()

