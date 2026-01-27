if(GIT_COMMIT)
    set(BUILD_ID "${GIT_COMMIT}")
else()
    execute_process(COMMAND git rev-parse HEAD
        WORKING_DIRECTORY ${libddwaf_SOURCE_DIR}
        OUTPUT_VARIABLE BUILD_ID
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
endif()

message(STATUS "Build id is ${BUILD_ID}")
string(SUBSTRING "${BUILD_ID}" 0 2 BUILD_ID_PREFIX)
string(SUBSTRING "${BUILD_ID}" 2 39 BUILD_ID_SUFFIX)

add_library(libddwaf_shared SHARED
    $<TARGET_OBJECTS:libddwaf_shared_objects> $<$<BOOL:${MSVC}>:libddwaf.def>)
set_target_properties(libddwaf_shared PROPERTIES OUTPUT_NAME ddwaf)

install(TARGETS libddwaf_shared EXPORT libddwaf-config
    DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if(LINUX)
    target_link_libraries(libddwaf_shared PUBLIC ${LIBDDWAF_INTERFACE_LIBRARIES})
    target_link_libraries(libddwaf_shared PRIVATE
        $<$<BOOL:${LIBDDWAF_ENABLE_LTO}>:-flto>
        -Wl,--no-undefined
        -Wl,-version-script=${libddwaf_SOURCE_DIR}/libddwaf.version
        -Wl,--build-id=0x${BUILD_ID}
        ${LIBDDWAF_PRIVATE_LIBRARIES}
        -static-libstdc++
        glibc_compat_time64 glibc_compat_math)

    if(NOT (CMAKE_BUILD_TYPE MATCHES Debug))
        set(SYMBOL_FILE $<TARGET_FILE:libddwaf_shared>.debug)
        add_custom_command(TARGET libddwaf_shared POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:libddwaf_shared> ${SYMBOL_FILE}
            COMMAND ${CMAKE_STRIP} --only-keep-debug ${SYMBOL_FILE}
            COMMAND ${CMAKE_STRIP} $<TARGET_FILE:libddwaf_shared>)

        install(FILES ${SYMBOL_FILE}
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/.build-id/${BUILD_ID_PREFIX}
            RENAME ${BUILD_ID_SUFFIX}.debug)
    endif()
elseif (APPLE)
    target_link_libraries(libddwaf_shared PRIVATE -Wl,-undefined,error libddwaf_shared_objects)

    if(NOT (CMAKE_BUILD_TYPE MATCHES Debug))
        # Ensure that dsymutil and strip is present
        find_program(DSYMUTIL dsymutil)
        if (DSYMUTIL STREQUAL "DSYMUTIL-NOTFOUND")
            message(FATAL_ERROR "dsymutil not found")
        endif()
        find_program(STRIP strip)
        if (STRIP STREQUAL "STRIP-NOTFOUND")
            message(FATAL_ERROR "strip not found")
        endif()

        set(SYMBOL_FILE $<TARGET_FILE:libddwaf_shared>.dwarf)
        add_custom_command(TARGET libddwaf_shared POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:libddwaf_shared> ${SYMBOL_FILE}
            COMMAND ${DSYMUTIL} --flat --minimize ${SYMBOL_FILE}
            COMMAND ${STRIP} -S -x $<TARGET_FILE:libddwaf_shared>
            COMMAND rm ${SYMBOL_FILE}
            COMMAND mv ${SYMBOL_FILE}.dwarf ${SYMBOL_FILE})

        install(FILES ${SYMBOL_FILE}
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/.build-id/${BUILD_ID_PREFIX}
            RENAME ${BUILD_ID_SUFFIX}.debug)
    endif()
elseif (MSVC)
    target_link_libraries(libddwaf_shared
        PRIVATE ${LIBDDWAF_PRIVATE_LIBRARIES}
        PUBLIC ${LIBDDWAF_INTERFACE_LIBRARIES})

    install(FILES $<TARGET_PDB_FILE:libddwaf_shared> DESTINATION lib OPTIONAL)
endif()
