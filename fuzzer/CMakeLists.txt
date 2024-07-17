MACRO(GET_DIRS subdirs parent)
  FILE(GLOB children RELATIVE ${parent} ${parent}/*)
  SET(subdirs "")
  FOREACH(child ${children})
    IF(IS_DIRECTORY ${parent}/${child})
      LIST(APPEND subdirs ${child})
    ENDIF()
  ENDFOREACH()
ENDMACRO()

GET_DIRS(subdirs ${CMAKE_CURRENT_SOURCE_DIR})

set(LINK_COMPILE_FLAGS -fsanitize=fuzzer,address,undefined,leak -fprofile-instr-generate -fcoverage-mapping)

gen_objects(fuzzer-common)
target_compile_options(fuzzer-common PRIVATE ${LINK_COMPILE_FLAGS})

foreach(dir ${subdirs})
    set(FUZZER_NAME "${dir}_fuzzer")
    file(GLOB_RECURSE FUZZER_SOURCE ${dir}/src/*.cpp)
    add_executable(${FUZZER_NAME} ${FUZZER_SOURCE})

    set_target_properties(${FUZZER_NAME} PROPERTIES
        CXX_STANDARD 20
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS NO
        COMPILE_FLAGS ${LINK_COMPILE_FLAGS}
        LINK_FLAGS ${LINK_COMPILE_FLAGS})

    target_include_directories(${FUZZER_NAME} PRIVATE ${LIBDDWAF_PUBLIC_INCLUDES} ${LIBDDWAF_PRIVATE_INCLUDES} ${CMAKE_CURRENT_SOURCE_DIR}/common/)
    target_link_libraries(${FUZZER_NAME} PRIVATE fuzzer-common lib_yamlcpp)
endforeach()

