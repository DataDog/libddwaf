# Files to clean
set_property(DIRECTORY PROPERTY ADDITIONAL_MAKE_CLEAN_FILES target)

set(CARGO_BUILD cargo build)
set(BUILD_BYPRODUCT "${CMAKE_CURRENT_SOURCE_DIR}/target/")

if (LINUX)
    if (NOT "${CMAKE_C_COMPILER_TARGET}" STREQUAL "")
        if ("{CMAKE_C_COMPILER_TARGET}" STREQUAL "i386-none-linux-musl")
            set(BUILD_TARGET "i686-unknown-linux-musl")
        else()
            string(REPLACE "none" "unknown" BUILD_TARGET ${CMAKE_C_COMPILER_TARGET})
        endif()
    endif()

    if (NOT "${BUILD_TARGET}" STREQUAL "")
        set(BUILD_BYPRODUCT "${BUILD_BYPRODUCT}/${BUILD_TARGET}/")
        set(CARGO_BUILD ${CARGO_BUILD} --target ${BUILD_TARGET})
    endif()
endif()

if (CMAKE_BUILD_TYPE MATCHES Release OR CMAKE_BUILD_TYPE MATCHES RelWithDebInfo)
    set(BUILD_BYPRODUCT "${BUILD_BYPRODUCT}/release/")
    set(CARGO_BUILD ${CARGO_BUILD} --release)
else()
    set(BUILD_BYPRODUCT "${BUILD_BYPRODUCT}/debug/")
endif()
set(BUILD_BYPRODUCT "${BUILD_BYPRODUCT}/libstring_checker${CMAKE_STATIC_LIBRARY_SUFFIX}")

add_custom_target(
    libstring_checker_build
    COMMAND ${CARGO_BUILD}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Compiling Rust library"
    BYPRODUCTS ${BUILD_BYPRODUCT}
)

add_library(libstring_checker STATIC IMPORTED GLOBAL)
set_target_properties(libstring_checker PROPERTIES  IMPORTED_LOCATION ${BUILD_BYPRODUCT})
target_include_directories(libstring_checker INTERFACE include)
add_dependencies(libstring_checker libstring_checker_build)
