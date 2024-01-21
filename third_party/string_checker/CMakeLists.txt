# Files to clean
set_property(DIRECTORY PROPERTY ADDITIONAL_MAKE_CLEAN_FILES target)

set(CARGO_BUILD cargo build)

if (LINUX)
    set(TARGET "")
    if (${arch} MATCHES "aarch64")
        set(TARGET "aarch64-unknown-linux-musl")
    elseif(${arch} MATCHES "armv7")
        set(TARGET "armv7-unknown-linux-musleabihf")
    elseif(${arch} MATCHES "x86_64")
        set(TARGET "x86_64-unknown-linux-musl")
    elseif(${arch} MATCHES "i386")
        set(TARGET "i386-unknown-linux-musl")
    endif()

    set(BUILD_BYPRODUCT "${CMAKE_CURRENT_SOURCE_DIR}/target/")
    if (${TARGET})
        set(BUILD_BYPRODUCT "${BUILD_BYPRODUCT}/${TARGET}/")
        set(CARGO_BUILD ${CARGO_BUILD} --target ${TARGET})
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
