find_program(CLANG_FORMAT clang-format)
if(CLANG_FORMAT STREQUAL CLANG_FORMAT-NOTFOUND)
    message(STATUS "Cannot find clang-format, either set CLANG_FORMAT or make it discoverable")
    return()
endif()

set(FILE_LIST "")
foreach(DIR IN ITEMS src tests validator perf fuzzing)
    file(GLOB_RECURSE SOURCE_FILES ${DIR}/*.hpp ${DIR}/*.cpp)
    list(APPEND FILE_LIST ${SOURCE_FILES})
endforeach()

add_custom_target(format
    COMMAND ${CLANG_FORMAT} -n -Werror ${FILE_LIST}
    COMMAND ${CMAKE_SOURCE_DIR}/cmake/check_headers.rb
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_custom_target(format_fix
    COMMAND ${CMAKE_SOURCE_DIR}/cmake/check_headers.rb --fix
    COMMAND ${CLANG_FORMAT} -i ${FILE_LIST}
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
