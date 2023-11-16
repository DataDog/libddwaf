file(GLOB LIBDDWAF_TOOL_SOURCE *.cpp)
file(GLOB LIBDDWAF_TOOL_COMMON_SOURCE common/*.cpp)

foreach(TOOL ${LIBDDWAF_TOOL_SOURCE})
    get_filename_component(TOOL_NAME ${TOOL} NAME_WLE)

    add_executable(${TOOL_NAME} ${TOOL} ${LIBDDWAF_TOOL_COMMON_SOURCE})
    target_link_options(${TOOL_NAME} PRIVATE ${LIBDDWAF_EXE_LINKER_FLAGS})
    target_link_libraries(${TOOL_NAME} PRIVATE libddwaf_objects lib_yamlcpp lib_rapidjson)
    target_include_directories(${TOOL_NAME} PRIVATE ${LIBDDWAF_PRIVATE_INCLUDES})

    set_target_properties(${TOOL_NAME} PROPERTIES
        CXX_STANDARD 20
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS NO)
endforeach()

