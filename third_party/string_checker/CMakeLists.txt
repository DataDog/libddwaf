# Files to clean
set_property(DIRECTORY PROPERTY ADDITIONAL_MAKE_CLEAN_FILES target)

add_custom_target(
    libstring_checker_build
    COMMAND cargo build --release
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Compiling Rust library"
    BYPRODUCTS ${CMAKE_CURRENT_SOURCE_DIR}/target/release/libstring_checker.a
)

add_library(libstring_checker STATIC IMPORTED GLOBAL)
set_target_properties(libstring_checker PROPERTIES  IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/target/release/libstring_checker.a)
target_include_directories(libstring_checker INTERFACE include)
add_dependencies(libstring_checker libstring_checker_build)
