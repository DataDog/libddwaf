cmake_minimum_required(VERSION 3.14)
file(READ "version" version)

project(libddwaf)
set(PROJECT_VERSION ${version})
set(CMAKE_PROJECT_VERSION ${version})

configure_file(src/version.hpp.in ${CMAKE_CURRENT_SOURCE_DIR}/src/version.hpp)

set(CMAKE_OSX_DEPLOYMENT_TARGET "10.12" CACHE STRING "Minimum OS X deployment version")
if(CMAKE_OSX_ARCHITECTURES MATCHES "x86_64" OR
  CMAKE_OSX_ARCHITECTURES MATCHES "arm64")
  set(CPU_TYPE ${CMAKE_OSX_ARCHITECTURES})
endif()

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(LIBDDWAF_SHARED_LINKER_FLAGS "-static-libstdc++" CACHE STRING "Shared library extra linker flags")
set(LIBDDWAF_EXE_LINKER_FLAGS "" CACHE STRING "Executable extra linker flags")
set(LIBDDWAF_PACKAGE_SUFFIX "" CACHE STRING "Suffix for packaging purposes")
if(CMAKE_OSX_ARCHITECTURES MATCHES "arm64")
    set(LIBDDWAF_PACKAGE_PROCESSOR ${CMAKE_OSX_ARCHITECTURES} CACHE STRING "Alternative processor for packaging purposes")
else()
    set(LIBDDWAF_PACKAGE_PROCESSOR ${CMAKE_SYSTEM_PROCESSOR} CACHE STRING "Alternative processor for packaging purposes")
endif()

option(LIBDDWAF_BUILD_SHARED "Build shared library" ON)
option(LIBDDWAF_BUILD_STATIC "Build shared library" ON)
option(LIBDDWAF_KEEP_SYMBOL_FILE "Keep the debug symbol file" ON)
option(LIBDDWAF_TESTING "Load test subdirectories and targets" ON)

if(CMAKE_BUILD_TYPE STREQUAL "")
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

set(LIBDDWAF_MSVC_RUNTIME_LIBRARY "/MT" CACHE STRING "MSVC RuntimeLibrary")

if(NOT MSVC)
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Wall -Wextra -Wno-narrowing")
    set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELEASE} -Wall -Wextra -Wno-narrowing -ggdb")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -Wextra -Wno-narrowing -ggdb")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wall -Wextra -Wno-narrowing")
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELEASE} -Wall -Wextra -Wno-narrowing -ggdb")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall -Wextra -Wno-narrowing -ggdb")

    add_definitions(-D__STDC_FORMAT_MACROS)
else()
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} ${LIBDDWAF_MSVC_RUNTIME_LIBRARY}")
    set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELEASE} ${LIBDDWAF_MSVC_RUNTIME_LIBRARY}")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} ${LIBDDWAF_MSVC_RUNTIME_LIBRARY}d")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} ${LIBDDWAF_MSVC_RUNTIME_LIBRARY}")
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELEASE} ${LIBDDWAF_MSVC_RUNTIME_LIBRARY}")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} ${LIBDDWAF_MSVC_RUNTIME_LIBRARY}d")

    add_definitions(-D_CRT_SECURE_NO_WARNINGS=1 -Dstrdup=_strdup -Dputenv=_putenv)
endif()

include(GNUInstallDirs)

add_subdirectory(third_party)

set(LIBDDWAF_SOURCE
    ${libddwaf_SOURCE_DIR}/src/clock.cpp
    ${libddwaf_SOURCE_DIR}/src/parameter.cpp
    ${libddwaf_SOURCE_DIR}/src/waf.cpp
    ${libddwaf_SOURCE_DIR}/src/interface.cpp
    ${libddwaf_SOURCE_DIR}/src/context.cpp
    ${libddwaf_SOURCE_DIR}/src/event.cpp
    ${libddwaf_SOURCE_DIR}/src/object.cpp
    ${libddwaf_SOURCE_DIR}/src/manifest.cpp
    ${libddwaf_SOURCE_DIR}/src/object_filter.cpp
    ${libddwaf_SOURCE_DIR}/src/object_store.cpp
    ${libddwaf_SOURCE_DIR}/src/condition.cpp
    ${libddwaf_SOURCE_DIR}/src/rule.cpp
    ${libddwaf_SOURCE_DIR}/src/ruleset_info.cpp
    ${libddwaf_SOURCE_DIR}/src/ip_utils.cpp
    ${libddwaf_SOURCE_DIR}/src/iterator.cpp
    ${libddwaf_SOURCE_DIR}/src/PWTransformer.cpp
    ${libddwaf_SOURCE_DIR}/src/utils.cpp
    ${libddwaf_SOURCE_DIR}/src/utf8.cpp
    ${libddwaf_SOURCE_DIR}/src/log.cpp
    ${libddwaf_SOURCE_DIR}/src/obfuscator.cpp
    ${libddwaf_SOURCE_DIR}/src/exclusion_filter.cpp
    ${libddwaf_SOURCE_DIR}/src/parser/parser.cpp
    ${libddwaf_SOURCE_DIR}/src/parser/parser_v1.cpp
    ${libddwaf_SOURCE_DIR}/src/parser/parser_v2.cpp
    ${libddwaf_SOURCE_DIR}/src/parser/rule_data_parser.cpp
    ${libddwaf_SOURCE_DIR}/src/rule_processor/phrase_match.cpp
    ${libddwaf_SOURCE_DIR}/src/rule_processor/regex_match.cpp
    ${libddwaf_SOURCE_DIR}/src/rule_processor/is_sqli.cpp
    ${libddwaf_SOURCE_DIR}/src/rule_processor/is_xss.cpp
    ${libddwaf_SOURCE_DIR}/src/rule_processor/ip_match.cpp
    ${libddwaf_SOURCE_DIR}/src/rule_processor/exact_match.cpp
)
add_library(libddwaf_objects OBJECT ${LIBDDWAF_SOURCE})

# we need PIC even on the static lib,as it's expected to be linked in a shared lib
set_target_properties(libddwaf_objects PROPERTIES
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
    POSITION_INDEPENDENT_CODE 1)

target_include_directories(libddwaf_objects PUBLIC ${libddwaf_SOURCE_DIR}/include)
target_include_directories(libddwaf_objects PRIVATE ${libddwaf_SOURCE_DIR}/src)
target_include_directories(libddwaf_objects PRIVATE ${libddwaf_SOURCE_DIR}/src/rule_processor)

install(FILES ${libddwaf_SOURCE_DIR}/include/ddwaf.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# System dependencies
set(LIBDDWAF_INTERFACE_LIBRARIES "")
set(LIBDDWAF_PRIVATE_LIBRARIES 
    lib_re2 lib_rapidjson lib_ac lib_injection lib_radix lib_utf8proc)

if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
# needed for glibc <2.17. We compile with --as-needed so the library won't
# be linked on more 2.17+, but dependencies might since it's part of the public
# interface of the target
    find_library(LIBPTHREAD pthread)
    if (LIBPTHREAD)
        list(APPEND LIBDDWAF_INTERFACE_LIBRARIES pthread)
    endif()
    find_library(LIBRT rt)
    if (LIBRT)
        list(APPEND LIBDDWAF_INTERFACE_LIBRARIES rt)
    endif()
    find_library(LIBDL dl)
    if (LIBDL)
        list(APPEND LIBDDWAF_INTERFACE_LIBRARIES dl)
    endif()
    # there is also a call to ceilf that may or may not result in an import.
    # The symbol might live in libm or the normal libc (e.g. musl). In any case,
    # add the dependency
    find_library(LIBM m)
    if (LIBM)
        list(APPEND LIBDDWAF_INTERFACE_LIBRARIES m)
    endif()
elseif(WIN32)
    list(APPEND LIBDDWAF_INTERFACE_LIBRARIES ws2_32)
endif()

target_link_libraries(libddwaf_objects
    PRIVATE ${LIBDDWAF_PRIVATE_LIBRARIES}
    INTERFACE ${LIBDDWAF_INTERFACE_LIBRARIES})

if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    target_link_options(libddwaf_objects PRIVATE -Wl,--as-needed)
endif()

# Static library
if (LIBDDWAF_BUILD_STATIC)
    add_library(libddwaf_static STATIC $<TARGET_OBJECTS:libddwaf_objects>)
    target_link_libraries(libddwaf_static INTERFACE ${LIBDDWAF_INTERFACE_LIBRARIES})
    if (NOT MSVC)
        set_target_properties(libddwaf_static PROPERTIES OUTPUT_NAME ddwaf)
    else()
        set_target_properties(libddwaf_static PROPERTIES OUTPUT_NAME ddwaf_static)
    endif()

    install(TARGETS libddwaf_static EXPORT libddwaf-config
        DESTINATION ${CMAKE_INSTALL_LIBDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

    # Post-processing on the static library
    if(MSVC)
        add_custom_command(TARGET libddwaf_static POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E make_directory lib_comb
            COMMAND ${CMAKE_COMMAND} -E chdir lib_comb lib.exe
                /OUT:combined${CMAKE_STATIC_LIBRARY_SUFFIX}
                $<TARGET_FILE:libddwaf_static> $<TARGET_FILE:lib_re2> $<TARGET_FILE:lib_ac>
                $<TARGET_FILE:lib_injection> $<TARGET_FILE:lib_utf8proc> $<TARGET_FILE:lib_radix>
            COMMAND ${CMAKE_COMMAND} -E copy lib_comb/combined${CMAKE_STATIC_LIBRARY_SUFFIX} $<TARGET_FILE:libddwaf_static>
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
    else()
        if(CMAKE_OSX_ARCHITECTURES MATCHES "arm64")
          add_custom_command(TARGET libddwaf_static POST_BUILD
              COMMAND ${CMAKE_COMMAND} -E make_directory ar_comb
              COMMAND ${CMAKE_COMMAND} -E chdir ar_comb ${CMAKE_AR} -x $<TARGET_FILE:libddwaf_static>
              COMMAND ${CMAKE_COMMAND} -E chdir ar_comb ${CMAKE_AR} -x $<TARGET_FILE:lib_re2>
              COMMAND ${CMAKE_COMMAND} -E chdir ar_comb ${CMAKE_AR} -x $<TARGET_FILE:lib_ac>
              COMMAND ${CMAKE_COMMAND} -E chdir ar_comb ${CMAKE_AR} -x $<TARGET_FILE:lib_injection>
              COMMAND ${CMAKE_COMMAND} -E chdir ar_comb ${CMAKE_AR} -x $<TARGET_FILE:lib_utf8proc>
              COMMAND ${CMAKE_COMMAND} -E chdir ar_comb ${CMAKE_AR} -x $<TARGET_FILE:lib_radix>
              COMMAND libtool -static -o ar_comb/combined.a -arch_only ${CMAKE_OSX_ARCHITECTURES} ar_comb/*.o*

              COMMAND ${CMAKE_COMMAND} -E copy ar_comb/combined${CMAKE_STATIC_LIBRARY_SUFFIX} $<TARGET_FILE:libddwaf_static>
              COMMAND rm -rf ar_comb
              WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
        else()
          add_custom_command(TARGET libddwaf_static POST_BUILD
              COMMAND ${CMAKE_COMMAND} -E make_directory ar_comb
              COMMAND ${CMAKE_COMMAND} -E chdir ar_comb ${CMAKE_AR} -x $<TARGET_FILE:libddwaf_static>
              COMMAND ${CMAKE_COMMAND} -E chdir ar_comb ${CMAKE_AR} -x $<TARGET_FILE:lib_re2>
              COMMAND ${CMAKE_COMMAND} -E chdir ar_comb ${CMAKE_AR} -x $<TARGET_FILE:lib_ac>
              COMMAND ${CMAKE_COMMAND} -E chdir ar_comb ${CMAKE_AR} -x $<TARGET_FILE:lib_injection>
              COMMAND ${CMAKE_COMMAND} -E chdir ar_comb ${CMAKE_AR} -x $<TARGET_FILE:lib_utf8proc>
              COMMAND ${CMAKE_COMMAND} -E chdir ar_comb ${CMAKE_AR} -x $<TARGET_FILE:lib_radix>
              COMMAND ${CMAKE_AR} -qcs ar_comb/combined${CMAKE_STATIC_LIBRARY_SUFFIX} ar_comb/*.o*

              COMMAND ${CMAKE_COMMAND} -E copy ar_comb/combined${CMAKE_STATIC_LIBRARY_SUFFIX} $<TARGET_FILE:libddwaf_static>
              COMMAND rm -rf ar_comb
              WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
      endif()
      if(NOT (CMAKE_BUILD_TYPE MATCHES Debug))
          if (CMAKE_SYSTEM_NAME STREQUAL Darwin OR CMAKE_SYSTEM_NAME STREQUAL Linux)
              find_program(STRIP strip)
              if (STRIP STREQUAL "STRIP-NOTFOUND")
                  message(FATAL_ERROR "strip not found")
              endif()
              add_custom_command(TARGET libddwaf_static POST_BUILD
                  COMMAND ${STRIP} -x -S $<TARGET_FILE:libddwaf_static> -o $<TARGET_FILE:libddwaf_static>.stripped)
              install(FILES $<TARGET_FILE:libddwaf_static>.stripped DESTINATION ${CMAKE_INSTALL_LIBDIR})
          endif()
      endif()
  endif()
endif()

# Shared library
if (LIBDDWAF_BUILD_SHARED)
    execute_process(COMMAND git rev-parse HEAD
        WORKING_DIRECTORY ${libddwaf_SOURCE_DIR}
        OUTPUT_VARIABLE BUILD_ID
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    message(STATUS "Build id is ${BUILD_ID}")
    string(SUBSTRING "${BUILD_ID}" 0 2 BUILD_ID_PREFIX)
    string(SUBSTRING "${BUILD_ID}" 2 39 BUILD_ID_SUFFIX)

    add_library(libddwaf_shared SHARED
        $<TARGET_OBJECTS:libddwaf_objects> $<$<BOOL:MSVC>:libddwaf.def>)
    set_target_properties(libddwaf_shared PROPERTIES OUTPUT_NAME ddwaf)

    install(TARGETS libddwaf_shared EXPORT libddwaf-config
        DESTINATION ${CMAKE_INSTALL_LIBDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

    if(CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")
        target_link_libraries(libddwaf_shared PRIVATE -Wl,-undefined,error libddwaf_objects)
    elseif(NOT MSVC)
        target_link_libraries(libddwaf_shared PUBLIC ${LIBDDWAF_INTERFACE_LIBRARIES})
        target_link_libraries(libddwaf_shared PRIVATE
            -Wl,--no-undefined
            -Wl,-version-script=${libddwaf_SOURCE_DIR}/libddwaf.version
            -Wl,--build-id=0x${BUILD_ID}
            ${LIBDDWAF_PRIVATE_LIBRARIES}
            ${LIBDDWAF_SHARED_LINKER_FLAGS})
    else()
        target_link_libraries(libddwaf_shared
            PRIVATE ${LIBDDWAF_PRIVATE_LIBRARIES}
            PUBLIC ${LIBDDWAF_INTERFACE_LIBRARIES})
    endif()

    if(NOT (CMAKE_BUILD_TYPE MATCHES Debug))
        if (CMAKE_SYSTEM_NAME STREQUAL Darwin)
            # Ensure that dsymutil and strip is present
            find_program(DSYMUTIL dsymutil)
            if (DSYMUTIL STREQUAL "DSYMUTIL-NOTFOUND")
                message(FATAL_ERROR "dsymutil not found")
            endif()
            find_program(STRIP strip)
            if (STRIP STREQUAL "STRIP-NOTFOUND")
                message(FATAL_ERROR "strip not found")
            endif()

            if(LIBDDWAF_KEEP_SYMBOL_FILE)
                set(SYMBOL_FILE $<TARGET_FILE:libddwaf_shared>.dwarf)
                add_custom_command(TARGET libddwaf_shared POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:libddwaf_shared> ${SYMBOL_FILE}
                    COMMAND ${DSYMUTIL} --flat --minimize ${SYMBOL_FILE}
                    COMMAND ${STRIP} -S -x $<TARGET_FILE:libddwaf_shared>
                    COMMAND rm ${SYMBOL_FILE}
                    COMMAND mv ${SYMBOL_FILE}.dwarf ${SYMBOL_FILE})
            else()
                add_custom_command(TARGET libddwaf_shared POST_BUILD
                    COMMAND ${STRIP} -S -x $<TARGET_FILE:libddwaf_shared>)
            endif()
        elseif(NOT WIN32)
            if(LIBDDWAF_KEEP_SYMBOL_FILE)
                set(SYMBOL_FILE $<TARGET_FILE:libddwaf_shared>.debug)
                add_custom_command(TARGET libddwaf_shared POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:libddwaf_shared> ${SYMBOL_FILE}
                    COMMAND ${CMAKE_STRIP} --only-keep-debug ${SYMBOL_FILE}
                    COMMAND ${CMAKE_STRIP} $<TARGET_FILE:libddwaf_shared>)
            else()
                add_custom_command(TARGET libddwaf_shared POST_BUILD
                    COMMAND ${CMAKE_STRIP} $<TARGET_FILE:libddwaf_shared>)
            endif()
        endif()

        if(LIBDDWAF_KEEP_SYMBOL_FILE AND NOT WIN32)
            install(FILES ${SYMBOL_FILE}
                DESTINATION ${CMAKE_INSTALL_LIBDIR}/.build-id/${BUILD_ID_PREFIX}
                RENAME ${BUILD_ID_SUFFIX}.debug)
        endif()
    endif()

    if (MSVC)
        install(FILES $<TARGET_PDB_FILE:libddwaf_shared> DESTINATION lib OPTIONAL)
    endif()
endif()

# Packaging
install(EXPORT libddwaf-config
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/cmake/libddwaf)
set(CPACK_PACKAGE_VENDOR "libddwaf")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "DataDog WAF Library")
set(CPACK_RESOURCE_FILE_README "${libddwaf_SOURCE_DIR}/README.md")
set(CPACK_GENERATOR "TGZ")
set(CPACK_SOURCE_GENERATOR "TGZ")

## Package name
execute_process(COMMAND git describe --exact-match --tags HEAD
    WORKING_DIRECTORY ${libddwaf_SOURCE_DIR}
    OUTPUT_VARIABLE DDWAF_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)

if (NOT DDWAF_VERSION)
    set(DDWAF_VERSION ${CMAKE_PROJECT_VERSION})
    execute_process(COMMAND git rev-parse --short HEAD
        WORKING_DIRECTORY ${libddwaf_SOURCE_DIR}
        OUTPUT_VARIABLE SHORT_BUILD_ID
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
endif()

set(CPACK_PACKAGE_FILE_NAME ${CMAKE_PROJECT_NAME}-${DDWAF_VERSION}-${CMAKE_SYSTEM_NAME}-${LIBDDWAF_PACKAGE_PROCESSOR})
if(LIBDDWAF_PACKAGE_SUFFIX MATCHES ".+")
    set(CPACK_PACKAGE_FILE_NAME ${CPACK_PACKAGE_FILE_NAME}-${LIBDDWAF_PACKAGE_SUFFIX})
endif()

if (SHORT_BUILD_ID)
    set(CPACK_PACKAGE_FILE_NAME ${CPACK_PACKAGE_FILE_NAME}-${SHORT_BUILD_ID})
endif()
string(TOLOWER ${CPACK_PACKAGE_FILE_NAME} CPACK_PACKAGE_FILE_NAME)

set(CPACK_WARN_ON_ABSOLUTE_INSTALL_DESTINATION TRUE)

include(CPack)

if (LIBDDWAF_TESTING)
    add_subdirectory(tests EXCLUDE_FROM_ALL)
    add_subdirectory(validator EXCLUDE_FROM_ALL)
    add_subdirectory(perf EXCLUDE_FROM_ALL)
    add_subdirectory(fuzzing EXCLUDE_FROM_ALL)
    add_subdirectory(examples EXCLUDE_FROM_ALL)

    include(cmake/clang-tidy.cmake)
    include(cmake/clang-format.cmake)
endif()
# vim: set et:
