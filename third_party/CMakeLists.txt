project(third_party)
include(ExternalProject)

set(DOWNLOAD_SUBDIR downloads)
set(INSTALL_DIR  ${CMAKE_BINARY_DIR}/third_party)
#get_filename_component(INSTALL_DIR ${CMAKE_BINARY_DIR}/third_party REALPATH)
#message("install dir is ${INSTALL_DIR}")

# workaround for using it in target_include_directories
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)

set(RAPIDJSON_COMMIT d87b698d0fcc10a5f632ecbc80a9cb2a8fa094a5)
ExternalProject_Add(proj_rapidjson
    URL               https://github.com/Tencent/rapidjson/archive/${RAPIDJSON_COMMIT}.tar.gz
    INSTALL_DIR       ${INSTALL_DIR}
    CMAKE_ARGS -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
               -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
               -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
               -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}
               -DCMAKE_CXX_FLAGS_RELEASE=${CMAKE_CXX_FLAGS_RELEASE}
               -DCMAKE_CXX_FLAGS_RELWITHDEBINFO=${CMAKE_CXX_FLAGS_RELWITHDEBINFO}
               -DCMAKE_CXX_FLAGS_DEBUG=${CMAKE_CXX_FLAGS_DEBUG}
               -DCMAKE_OSX_ARCHITECTURES=${CMAKE_OSX_ARCHITECTURES}
    BUILD_COMMAND     ""
    INSTALL_COMMAND   ${CMAKE_COMMAND} -E copy_directory "<SOURCE_DIR>/include/" "<INSTALL_DIR>/include/"
)
add_library(lib_rapidjson INTERFACE IMPORTED GLOBAL)
target_include_directories(lib_rapidjson INTERFACE ${INSTALL_DIR}/include)
add_dependencies(lib_rapidjson proj_rapidjson)
target_compile_definitions(lib_rapidjson INTERFACE RAPIDJSON_HAS_STDSTRING=1)

if(MSVC)
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /MT")
    set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELEASE} /MT")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /MTd")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELEASE} /MT")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")
else()
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -fPIC")
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELEASE} -fPIC")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fPIC")
endif()

# To avoid building everything for re2, including test binvaries:
#     BUILD_COMMAND cmake --build <BINARY_DIR> --target re2
# But this is not enough, because the install target run afterwards insists on building everything
set(RE2_COMMIT b83705e2d297f21b0805202bac86c935670634f8)
ExternalProject_Add(proj_re2
    URL         https://github.com/google/re2/archive/${RE2_COMMIT}.tar.gz
    INSTALL_DIR ${INSTALL_DIR}
    CMAKE_ARGS -DCMAKE_VERBOSE_MAKEFILE=1 -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
    -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
    -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
    -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}
    -DCMAKE_CXX_FLAGS_RELEASE=${CMAKE_CXX_FLAGS_RELEASE}
    -DCMAKE_CXX_FLAGS_RELWITHDEBINFO=${CMAKE_CXX_FLAGS_RELWITHDEBINFO}
    -DCMAKE_CXX_FLAGS_DEBUG=${CMAKE_CXX_FLAGS_DEBUG}
    -DCMAKE_OSX_ARCHITECTURES=${CMAKE_OSX_ARCHITECTURES}
    -DRE2_BUILD_TESTING=0
)
# alas, we can't use find_package because by the package is not downloaded by config time
# so manually creating the library
add_library(lib_re2 STATIC IMPORTED GLOBAL)
set_property(TARGET lib_re2 PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/${CMAKE_INSTALL_LIBDIR}/${CMAKE_STATIC_LIBRARY_PREFIX}re2${CMAKE_STATIC_LIBRARY_SUFFIX})
target_include_directories(lib_re2 INTERFACE ${INSTALL_DIR}/include)
if(NOT MSVC)
    target_link_libraries(lib_re2 INTERFACE -lpthread)
endif()
add_dependencies(lib_re2 proj_re2)

set(GOOGLETEST_COMMIT 955c7f837efad184ec63e771c42542d37545eaef)
ExternalProject_Add(proj_gtest
    URL         https://github.com/google/googletest/archive/${GOOGLETEST_COMMIT}.tar.gz
    INSTALL_DIR ${INSTALL_DIR}
    CMAKE_ARGS  -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
                -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
                -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
                -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
                -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}
                -DCMAKE_CXX_FLAGS_RELEASE=${CMAKE_CXX_FLAGS_RELEASE}
                -DCMAKE_CXX_FLAGS_RELWITHDEBINFO=${CMAKE_CXX_FLAGS_RELWITHDEBINFO}
                -DCMAKE_CXX_FLAGS_DEBUG=${CMAKE_CXX_FLAGS_DEBUG}
                -DCMAKE_OSX_ARCHITECTURES=${CMAKE_OSX_ARCHITECTURES}
                -DBUILD_SHARED_LIBS=0
                -DBUILD_GMOCK=0
)
if(CMAKE_BUILD_TYPE MATCHES Debug)
    set(LIBGTEST_FILENAME ${CMAKE_STATIC_LIBRARY_PREFIX}gtestd${CMAKE_STATIC_LIBRARY_SUFFIX})
else()
    set(LIBGTEST_FILENAME ${CMAKE_STATIC_LIBRARY_PREFIX}gtest${CMAKE_STATIC_LIBRARY_SUFFIX})
endif()

add_library(lib_gtest STATIC IMPORTED GLOBAL)
set_property(TARGET lib_gtest PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/${CMAKE_INSTALL_LIBDIR}/${LIBGTEST_FILENAME})
target_include_directories(lib_gtest INTERFACE ${INSTALL_DIR}/include)
if(NOT MSVC)
    target_link_libraries(lib_gtest INTERFACE -lpthread)
endif()
add_dependencies(lib_gtest proj_gtest)
set_target_properties(lib_gtest proj_gtest PROPERTIES EXCLUDE_FROM_ALL TRUE)

add_library(lib_injection STATIC
    libinjection/src/xss.c
    libinjection/src/libinjection_html5.c
    libinjection/src/libinjection_xss.c
    libinjection/src/libinjection_sqli.c)
target_include_directories(lib_injection INTERFACE ${PROJECT_SOURCE_DIR}/libinjection/src)
set_target_properties(lib_injection PROPERTIES POSITION_INDEPENDENT_CODE 1)

add_library(lib_ac STATIC
    lua-aho-corasick/ac_fast.cxx
    lua-aho-corasick/ac_slow.cxx
    lua-aho-corasick/ac.cxx)
target_include_directories(lib_ac INTERFACE ${PROJECT_SOURCE_DIR}/lua-aho-corasick)
set_target_properties(lib_ac PROPERTIES POSITION_INDEPENDENT_CODE 1)

# yaml-cpp
ExternalProject_Add(proj_yamlcpp
    URL               https://github.com/jbeder/yaml-cpp/archive/refs/tags/yaml-cpp-0.6.3.zip
    INSTALL_DIR       ${INSTALL_DIR}
    CMAKE_ARGS  -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
                -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
                -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
                -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}
                -DCMAKE_CXX_FLAGS_RELEASE=${CMAKE_CXX_FLAGS_RELEASE}
                -DCMAKE_CXX_FLAGS_RELWITHDEBINFO=${CMAKE_CXX_FLAGS_RELWITHDEBINFO}
                -DCMAKE_CXX_FLAGS_DEBUG=${CMAKE_CXX_FLAGS_DEBUG}
                -DYAML_CPP_BUILD_TESTS=OFF
                -DYAML_CPP_BUILD_CONTRIB=OFF
                -DYAML_CPP_BUILD_TOOLS=OFF
                -DYAML_CPP_INSTALL=ON
                -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
                -DCMAKE_OSX_ARCHITECTURES=${CMAKE_OSX_ARCHITECTURES}
)
add_library(lib_yamlcpp STATIC IMPORTED GLOBAL)
if (NOT MSVC)
    set(LIBYAML_FILENAME libyaml-cpp${CMAKE_STATIC_LIBRARY_SUFFIX})
else()
    set(LIBYAML_FILENAME libyaml-cppmd${CMAKE_STATIC_LIBRARY_SUFFIX})
endif()
set_target_properties(lib_yamlcpp PROPERTIES  IMPORTED_LOCATION ${INSTALL_DIR}/lib/${LIBYAML_FILENAME})
target_include_directories(lib_yamlcpp INTERFACE ${INSTALL_DIR}/include)
add_dependencies(lib_yamlcpp proj_yamlcpp)
set_target_properties(lib_yamlcpp proj_yamlcpp PROPERTIES EXCLUDE_FROM_ALL TRUE)
# vim: et
