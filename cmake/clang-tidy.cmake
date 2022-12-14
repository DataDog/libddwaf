find_program(CLANG_TIDY run-clang-tidy)
if(CLANG_TIDY STREQUAL CLANG_TIDY-NOTFOUND)
    message(STATUS "Cannot find clang-tidy, either set CLANG_TIDY or make it discoverable")
    return()
endif()

file(GLOB_RECURSE FILE_LIST src/*.hpp src/*.cpp)

execute_process (
    COMMAND bash -c "${CLANG_TIDY} --help | grep -qs 'use-color'"
    RESULT_VARIABLE USE_COLOR
)

set(COLOR_OPT "")
if (USE_COLOR EQUAL 0)
    set(COLOR_OPT -use-color)
endif()

add_custom_target(tidy
    COMMAND ${CLANG_TIDY} ${COLOR_OPT} -p ${CMAKE_BINARY_DIR} ${FILE_LIST}
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_custom_target(tidy_fix
    COMMAND ${CLANG_TIDY} ${COLOR_OPT} -fix -p ${CMAKE_BINARY_DIR} ${FILE_LIST}
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
