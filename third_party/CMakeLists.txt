project(third_party)
include(ExternalProject)

set(DOWNLOAD_SUBDIR downloads)
set(INSTALL_DIR  ${CMAKE_BINARY_DIR}/third_party)
#get_filename_component(INSTALL_DIR ${CMAKE_BINARY_DIR}/third_party REALPATH)
#message("install dir is ${INSTALL_DIR}")

# workaround for using it in target_include_directories
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)

if(NOT MSVC)
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wno-unused-parameter")
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELEASE} -Wno-unused-parameter")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wno-unused-parameter")
endif()

set(RAPIDJSON_COMMIT 22a62fcc2c2fa2418f5d358cdf65c1df73b418ae)
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
set_target_properties(proj_rapidjson PROPERTIES EXCLUDE_FROM_ALL TRUE)

if(NOT MSVC)
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -fPIC")
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELEASE} -fPIC")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fPIC")
endif()

if(CMAKE_BUILD_TYPE MATCHES Debug)
    set(LIBGTEST_FILENAME ${CMAKE_STATIC_LIBRARY_PREFIX}gtestd${CMAKE_STATIC_LIBRARY_SUFFIX})
    set(LIBGMOCK_FILENAME ${CMAKE_STATIC_LIBRARY_PREFIX}gmockd${CMAKE_STATIC_LIBRARY_SUFFIX})
else()
    set(LIBGTEST_FILENAME ${CMAKE_STATIC_LIBRARY_PREFIX}gtest${CMAKE_STATIC_LIBRARY_SUFFIX})
    set(LIBGMOCK_FILENAME ${CMAKE_STATIC_LIBRARY_PREFIX}gmock${CMAKE_STATIC_LIBRARY_SUFFIX})
endif()

set(GOOGLETEST_COMMIT 955c7f837efad184ec63e771c42542d37545eaef)
ExternalProject_Add(proj_gtest
    URL         https://github.com/google/googletest/archive/${GOOGLETEST_COMMIT}.tar.gz
    INSTALL_DIR ${INSTALL_DIR}
    CMAKE_ARGS  -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
                -DCMAKE_INSTALL_LIBDIR=lib
                -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
                -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
                -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
                -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}
                -DCMAKE_CXX_FLAGS_RELEASE=${CMAKE_CXX_FLAGS_RELEASE}
                -DCMAKE_CXX_FLAGS_RELWITHDEBINFO=${CMAKE_CXX_FLAGS_RELWITHDEBINFO}
                -DCMAKE_CXX_FLAGS_DEBUG=${CMAKE_CXX_FLAGS_DEBUG}
                -DCMAKE_OSX_ARCHITECTURES=${CMAKE_OSX_ARCHITECTURES}
                -DBUILD_SHARED_LIBS=0
                -DBUILD_GMOCK=ON
                BUILD_BYPRODUCTS ${INSTALL_DIR}/lib/${LIBGTEST_FILENAME} ${INSTALL_DIR}/lib/${LIBGMOCK_FILENAME}
)

add_library(lib_gtest STATIC IMPORTED GLOBAL)
add_library(lib_gmock STATIC IMPORTED GLOBAL)
set_property(TARGET lib_gtest PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/${LIBGTEST_FILENAME})
set_property(TARGET lib_gmock PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/${LIBGMOCK_FILENAME})
target_include_directories(lib_gtest INTERFACE ${INSTALL_DIR}/include)
target_include_directories(lib_gmock INTERFACE ${INSTALL_DIR}/include)
if(NOT MSVC)
    target_link_libraries(lib_gtest INTERFACE -lpthread)
    target_link_libraries(lib_gmock INTERFACE -lpthread)
endif()

add_dependencies(lib_gtest proj_gtest)
add_dependencies(lib_gmock proj_gtest)
set_target_properties(lib_gtest lib_gmock proj_gtest PROPERTIES EXCLUDE_FROM_ALL TRUE)

# yaml-cpp
if (NOT MSVC)
    if(CMAKE_BUILD_TYPE MATCHES Debug)
        set(LIBYAML_FILENAME libyaml-cppd${CMAKE_STATIC_LIBRARY_SUFFIX})
    else()
        set(LIBYAML_FILENAME libyaml-cpp${CMAKE_STATIC_LIBRARY_SUFFIX})
    endif()
else()
    set(LIBYAML_FILENAME yaml-cpp${CMAKE_STATIC_LIBRARY_SUFFIX})
endif()

ExternalProject_Add(proj_yamlcpp
    URL https://github.com/jbeder/yaml-cpp/archive/refs/tags/yaml-cpp-0.7.0.zip
    INSTALL_DIR       ${INSTALL_DIR}
    CMAKE_ARGS  -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
                -DCMAKE_INSTALL_LIBDIR=lib
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
                -DYAML_BUILD_SHARED_LIBS=OFF
                -DYAML_MSVC_SHARED_RT=OFF
                -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
                -DCMAKE_OSX_ARCHITECTURES=${CMAKE_OSX_ARCHITECTURES}
                BUILD_BYPRODUCTS ${INSTALL_DIR}/lib/${LIBYAML_FILENAME}
)
add_library(lib_yamlcpp STATIC IMPORTED GLOBAL)
set_target_properties(lib_yamlcpp PROPERTIES  IMPORTED_LOCATION ${INSTALL_DIR}/lib/${LIBYAML_FILENAME})
target_include_directories(lib_yamlcpp INTERFACE ${INSTALL_DIR}/include)
add_dependencies(lib_yamlcpp proj_yamlcpp)
set_target_properties(lib_yamlcpp proj_yamlcpp PROPERTIES EXCLUDE_FROM_ALL TRUE)

# Appsec event rules
ExternalProject_Add(proj_event_rules
    GIT_REPOSITORY git@github.com:DataDog/appsec-event-rules.git
    GIT_TAG 1.9.0
    GIT_SHALLOW ON
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND "")

set_target_properties(proj_event_rules PROPERTIES EXCLUDE_FROM_ALL TRUE)

add_subdirectory(abseil-cpp)

set(TCMALLOC_SOURCE
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/tcmalloc.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/common.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/internal/memory_stats.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/internal/cache_topology.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/experiment.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/allocation_sample.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/internal/util.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/internal/logging.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/central_freelist.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/transfer_cache.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/arena.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/system-alloc.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/malloc_extension.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/internal/page_size.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/internal/pageflags.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/pagemap.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/parameters.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/global_stats.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/static_vars.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/peak_heap_tracker.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/thread_cache.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/deallocation_profiler.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/span.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/stats.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/page_allocator.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/page_allocator_interface.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/huge_page_aware_allocator.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/huge_allocator.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/huge_cache.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/guarded_page_allocator.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/huge_address_map.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/internal/environment.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/stack_trace_table.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/internal/percpu_rseq_unsupported.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/internal/percpu.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/internal/percpu_tcmalloc.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/internal/numa.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/internal/sysinfo.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/sampler.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/cpu_cache.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/sizemap.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/size_classes.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/internal/mincore.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/experimental_pow2_size_class.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/lowfrag_size_classes.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/legacy_size_classes.cc
 ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc/tcmalloc/internal/percpu_rseq_asm.S
)

enable_language(ASM)

add_library(tcmalloc STATIC ${TCMALLOC_SOURCE})

target_compile_options(tcmalloc PRIVATE
    -Wno-deprecated-declarations
    -Wno-implicit-int-float-conversion
    -Wno-sign-compare
    -Wno-uninitialized
    -Wno-unused-function
    -Wno-unused-variable
    -Wno-type-limits
    -Wno-missing-field-initializers
    -Wno-attribute-alias
    -Wignored-qualifiers)

set_target_properties(tcmalloc PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    POSITION_INDEPENDENT_CODE ON
)

target_include_directories(tcmalloc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tcmalloc)
target_link_libraries(tcmalloc PRIVATE
    "absl::algorithm_container"
    "absl::base"
    "absl::config"
    "absl::core_headers"
    "absl::dynamic_annotations"
    "absl::fixed_array"
    "absl::stacktrace"
    "absl::symbolize"
    "absl::synchronization"
    "absl::status"
    "absl::statusor"
    "absl::hash"
    "absl::memory"
    "absl::strings"
    "absl::str_format"
    "absl::time"
    "absl::optional"
    "absl::span"
    "absl::bits"
    "absl::raw_logging_internal"
    "absl::cord"
    "absl::cord_internal"
    "absl::flat_hash_set"
)
# vim: et
