include(ExternalProject)

if(NOT MSVC)
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -fPIC")
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELEASE} -fPIC")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fPIC")
endif()

set(INSTALL_DIR  ${CMAKE_BINARY_DIR}/reflex)
if (NOT MSVC)
    set (LIBREFLEX_FILENAME libreflex_static_lib${CMAKE_STATIC_LIBRARY_SUFFIX})
    set(REFLEX_EXECUTABLE ${INSTALL_DIR}/bin/reflex)
else()
    set (LIBREFLEX_FILENAME reflex_static_lib${CMAKE_STATIC_LIBRARY_SUFFIX})
    set(REFLEX_EXECUTABLE ${INSTALL_DIR}/bin/reflex.exe)
endif()

set(REFLEX_INCLUDE_DIR ${INSTALL_DIR}/include)
set(REFLEX_STATIC_LIB ${INSTALL_DIR}/lib/${LIBREFLEX_FILENAME})

file(MAKE_DIRECTORY ${REFLEX_INCLUDE_DIR})
ExternalProject_Add(proj_reflex
    GIT_REPOSITORY  https://github.com/Genivia/RE-flex.git
    GIT_TAG v4.1.0
    GIT_SHALLOW ON
    INSTALL_DIR ${INSTALL_DIR}
    CMAKE_ARGS  -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
                -DCMAKE_INSTALL_LIBDIR=lib
                -DCMAKE_INSTALL_BINDIR=bin
                -DCMAKE_INSTALL_INCLUDEDIR=include
                -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
                -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
                -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}
                -DCMAKE_CXX_FLAGS_RELEASE=${CMAKE_CXX_FLAGS_RELEASE}
                -DCMAKE_CXX_FLAGS_RELWITHDEBINFO=${CMAKE_CXX_FLAGS_RELWITHDEBINFO}
                -DCMAKE_CXX_FLAGS_DEBUG=${CMAKE_CXX_FLAGS_DEBUG}
                -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
                -DCMAKE_OSX_ARCHITECTURES=${CMAKE_OSX_ARCHITECTURES}
    BUILD_BYPRODUCTS ${REFLEX_STATIC_LIB}
                     ${REFLEX_INCLUDE_DIR}
                     ${REFLEX_EXECUTABLE}
)

add_library(libreflex STATIC IMPORTED GLOBAL)
set_target_properties(libreflex PROPERTIES  IMPORTED_LOCATION ${REFLEX_STATIC_LIB})
target_include_directories(libreflex INTERFACE ${REFLEX_INCLUDE_DIR})
add_dependencies(libreflex proj_reflex)

macro(reflex_target target input output)
    if(NOT IS_ABSOLUTE "${input}")
        set(_REFLEX_INPUT "${libddwaf_SOURCE_DIR}/src/${input}")
    else()
        set(_REFLEX_INPUT ${input})
    endif()

    set(_REFLEX_WORKING_DIR "${CMAKE_CURRENT_BINARY_DIR}")
    if(NOT IS_ABSOLUTE ${output})
        set(_REFLEX_OUTPUT "${libddwaf_SOURCE_DIR}/src/${output}")
    else()
        set(_REFLEX_OUTPUT "${output}")
    endif()

    add_custom_command(OUTPUT ${_REFLEX_OUTPUT}
        COMMAND ${REFLEX_EXECUTABLE} -o${_REFLEX_OUTPUT} ${_REFLEX_INPUT}
        VERBATIM
        DEPENDS ${_REFLEX_INPUT} ${REFLEX_EXECUTABLE}
        COMMENT "Generating ${_REFLEX_OUTPUT}"
        WORKING_DIRECTORY ${_REFLEX_WORKING_DIR})
        #BYPRODUCTS ${_REFLEX_OUTPUT})
    add_custom_target(reflex_gen_${target} DEPENDS "${_REFLEX_OUTPUT}")
    add_dependencies(reflex_gen_${target} proj_reflex)

    set(REFLEX_${target}_OUTPUT ${_REFLEX_OUTPUT})

    unset(_REFLEX_OUTPUT)
    unset(_REFLEX_INPUT)
    unset(_REFLEX_WORKING_DIR)
endmacro()

