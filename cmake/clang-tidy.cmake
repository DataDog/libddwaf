find_program(CLANG_TIDY clang-tidy)
if(CLANG_TIDY STREQUAL CLANG_TIDY-NOTFOUND)
    message(STATUS "Cannot find clang-tidy, either set CLANG_TIDY or make it discoverable")
    return()
endif()

file(GLOB_RECURSE FILE_LIST src/*.hpp src/*.cpp)

add_custom_target(tidy
    COMMAND ${CLANG_TIDY} -p ${CMAKE_BINARY_DIR} ${FILE_LIST}
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_custom_target(tidy_fix
    COMMAND ${CLANG_TIDY} --fix -p ${CMAKE_BINARY_DIR} ${FILE_LIST}
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
