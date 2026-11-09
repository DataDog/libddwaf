add_library(libddwaf_static STATIC $<TARGET_OBJECTS:libddwaf_static_objects>)
if(LINUX AND LIBDDWAF_BUNDLE_LIBM_IN_STATIC)
    # Static library consumers may link it into a shared library
    target_sources(libddwaf_static PRIVATE
        ${libddwaf_SOURCE_DIR}/src/compat/ceilf.c)
    set_target_properties(libddwaf_static PROPERTIES POSITION_INDEPENDENT_CODE 1)
endif()

target_link_libraries(libddwaf_static INTERFACE ${LIBDDWAF_STATIC_INTERFACE_LIBRARIES})
if (NOT MSVC)
    set_target_properties(libddwaf_static PROPERTIES OUTPUT_NAME ddwaf)
else()
    set_target_properties(libddwaf_static PROPERTIES OUTPUT_NAME ddwaf_static)
endif()

install(TARGETS libddwaf_static EXPORT libddwaf-config
    DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if(NOT (CMAKE_BUILD_TYPE MATCHES Debug) AND (APPLE OR LINUX))
    if (NOT CMAKE_STRIP)
        find_program(STRIP strip)
        if (STRIP STREQUAL "STRIP-NOTFOUND")
            message(FATAL_ERROR "strip not found")
        endif()
    else()
        set(STRIP ${CMAKE_STRIP})
    endif()
    add_custom_command(TARGET libddwaf_static POST_BUILD
      COMMAND ${STRIP} -x -S $<TARGET_FILE:libddwaf_static> -o $<TARGET_FILE:libddwaf_static>.stripped)
    install(FILES $<TARGET_FILE:libddwaf_static>.stripped DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()

