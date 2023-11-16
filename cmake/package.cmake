# Packaging

install(FILES ${libddwaf_SOURCE_DIR}/include/ddwaf.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT libddwaf-config DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/cmake/libddwaf)

if(APPLE AND CMAKE_OSX_ARCHITECTURES MATCHES "arm64")
    set(LIBDDWAF_PACKAGE_PROCESSOR ${CMAKE_OSX_ARCHITECTURES} CACHE STRING "Alternative processor for packaging purposes")
else()
    set(LIBDDWAF_PACKAGE_PROCESSOR ${CMAKE_SYSTEM_PROCESSOR} CACHE STRING "Alternative processor for packaging purposes")
endif()

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
if (SHORT_BUILD_ID)
    set(CPACK_PACKAGE_FILE_NAME ${CPACK_PACKAGE_FILE_NAME}-${SHORT_BUILD_ID})
endif()
string(TOLOWER ${CPACK_PACKAGE_FILE_NAME} CPACK_PACKAGE_FILE_NAME)

set(CPACK_WARN_ON_ABSOLUTE_INSTALL_DESTINATION TRUE)

include(CPack)
