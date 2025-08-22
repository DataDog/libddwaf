cmake_minimum_required(VERSION 3.16)
project(libddwaf_afl_fuzzers)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include our resource embedding function
include(cmake/embed_resources.cmake)

# Set up include directories
include_directories(../src)
include_directories(../include)
include_directories(../src/vendor)
include_directories(../src/vendor/fmt)
include_directories(../src/vendor/re2)
include_directories(../src/vendor/libinjection/src)
include_directories(../src/vendor/radixlib)
include_directories(../src/vendor/utf8proc)
include_directories(../src/vendor/lua-aho-corasick)
include_directories(common)

# Add libddwaf as a dependency (assuming it's built in parent directory)
set(LIBDDWAF_BUILD_DIR "${CMAKE_SOURCE_DIR}/../build")
set(LIBDDWAF_SRC_DIR "${CMAKE_SOURCE_DIR}/../src")

# Add the libddwaf library path
link_directories(${LIBDDWAF_BUILD_DIR})

# Add third_party dependencies (including RapidJSON) only if not already included
if(NOT TARGET lib_rapidjson)
    add_subdirectory(../third_party third_party EXCLUDE_FROM_ALL)
endif()

# Function to create a fuzzer target
function(add_afl_fuzzer target_name source_files)
    add_executable(${target_name} ${source_files})
    
    # Link against necessary libraries
    target_link_libraries(${target_name} 
        libddwaf_objects
    )
    
    # Special handling for global fuzzer - needs YAML-CPP
    if(${target_name} STREQUAL "global_fuzz")
        target_link_libraries(${target_name} lib_yamlcpp)
    endif()
    # Add the json_utils.cpp source to the target
    target_sources(${target_name} PRIVATE 
        ../tests/common/json_utils.cpp
    )
    
    # Include tests directory for json_utils.hpp
    target_include_directories(${target_name} PRIVATE 
        ../tests
    )
    
    # Special handling for e2e fuzzer - embed JSON configs
    if(${target_name} STREQUAL "e2e_fuzz")
        # Find all JSON files in the e2e/src/ruleset directory
        file(GLOB E2E_JSON_FILES "${CMAKE_CURRENT_SOURCE_DIR}/e2e/src/ruleset/*.json")
        
        # Generate embedded resources header
        set(EMBEDDED_HEADER "${CMAKE_BINARY_DIR}/generated/embedded_configs.hpp")
        embed_json_files(${target_name}
            OUTPUT_FILE ${EMBEDDED_HEADER}
            NAMESPACE "embedded_configs"
            JSON_FILES ${E2E_JSON_FILES}
        )
        
        # Add the generated header to include path
        target_include_directories(${target_name} PRIVATE ${CMAKE_BINARY_DIR}/generated)
        
        # Make sure the embedded resources are generated before building
        add_dependencies(${target_name} ${target_name}_resources)
    endif()
    
    # Special handling for global fuzzer - embed YAML config
    if(${target_name} STREQUAL "global_fuzz")
        # Find the sample_rules.yml file in the global directory
        set(GLOBAL_YAML_FILE "${CMAKE_CURRENT_SOURCE_DIR}/global/sample_rules.yml")
        
        # Generate embedded resources header
        set(EMBEDDED_HEADER "${CMAKE_BINARY_DIR}/generated/embedded_rules.hpp")
        embed_yaml_files(${target_name}
            OUTPUT_FILE ${EMBEDDED_HEADER}
            NAMESPACE "embedded_rules"
            YAML_FILES ${GLOBAL_YAML_FILE}
        )
        
        # Add the generated header to include path
        target_include_directories(${target_name} PRIVATE ${CMAKE_BINARY_DIR}/generated)
        
        # Make sure the embedded resources are generated before building
        add_dependencies(${target_name} ${target_name}_resources)
    endif()
    
    # AFL++ instrumentation is handled automatically by afl compiler
    # Set output directory
    set_target_properties(${target_name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
    )
endfunction()

# Create fuzzer targets
# Find all fuzzer targets in individual directories with src/main.cpp structure
file(GLOB FUZZER_SOURCES "*/src/main.cpp")

set(FUZZER_TARGETS "")
set(CORPUS_DIRS "")

foreach(FUZZER_SOURCE ${FUZZER_SOURCES})
    # Extract the directory name (fuzzer name) from the path
    get_filename_component(FUZZER_DIR ${FUZZER_SOURCE} DIRECTORY)
    get_filename_component(FUZZER_NAME ${FUZZER_DIR} DIRECTORY)
    get_filename_component(FUZZER_NAME ${FUZZER_NAME} NAME)
    
    # Collect all source files for this fuzzer
    set(FUZZER_ALL_SOURCES ${FUZZER_SOURCE})
    
    # Find all other .cpp files in the same src directory
    file(GLOB ADDITIONAL_SOURCES "${FUZZER_DIR}/*.cpp")
    foreach(ADDITIONAL_SOURCE ${ADDITIONAL_SOURCES})
        # Skip main.cpp since it's already included
        get_filename_component(ADDITIONAL_NAME ${ADDITIONAL_SOURCE} NAME)
        if(NOT ${ADDITIONAL_NAME} STREQUAL "main.cpp")
            list(APPEND FUZZER_ALL_SOURCES ${ADDITIONAL_SOURCE})
        endif()
    endforeach()
    
    # Create the fuzzer target with all source files
    add_afl_fuzzer(${FUZZER_NAME}_fuzz "${FUZZER_ALL_SOURCES}")
    
    # Add to our lists for dependencies and corpus creation
    list(APPEND FUZZER_TARGETS ${FUZZER_NAME}_fuzz)
    list(APPEND CORPUS_DIRS ${FUZZER_NAME})
endforeach()

# Generate corpus files during configuration phase if they don't exist
if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/global/sample_rules.yml")
    message(STATUS "Generating corpus files using build_corpus.py...")
    execute_process(
        COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/global/scripts/build_corpus.py
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/..
        RESULT_VARIABLE BUILD_CORPUS_RESULT
        OUTPUT_VARIABLE BUILD_CORPUS_OUTPUT
        ERROR_VARIABLE BUILD_CORPUS_ERROR
    )
    if(NOT BUILD_CORPUS_RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to generate corpus files: ${BUILD_CORPUS_ERROR}")
    endif()
    message(STATUS "Corpus files generated successfully")
endif()

# Create a target to build corpus using Python script (for manual rebuilding)
add_custom_target(build_corpus
    COMMAND ${CMAKE_COMMAND} -E echo "Building corpus using build_corpus.py..."
    COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/global/scripts/build_corpus.py
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/..
    COMMENT "Regenerating corpus files and sample data for fuzzing"
    VERBATIM
)

# Create a target to build all fuzzers
add_custom_target(all_fuzzers DEPENDS ${FUZZER_TARGETS})

# Create a target to set up the fuzzing environment
add_custom_target(setup_fuzzing
    DEPENDS all_fuzzers build_corpus
)
