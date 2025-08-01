cmake_minimum_required(VERSION 3.16)
project(libddwaf_afl_fuzzers)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

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

# Function to create a fuzzer target
function(add_afl_fuzzer target_name source_file)
    add_executable(${target_name} ${source_file})
    
    # Link against necessary libraries
    target_link_libraries(${target_name} 
        ${LIBDDWAF_BUILD_DIR}/libddwaf.a
        pthread
    )
    
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
    
    # Create the fuzzer target
    add_afl_fuzzer(${FUZZER_NAME}_fuzz ${FUZZER_SOURCE})
    
    # Add to our lists for dependencies and corpus creation
    list(APPEND FUZZER_TARGETS ${FUZZER_NAME}_fuzz)
    list(APPEND CORPUS_DIRS ${FUZZER_NAME})
endforeach()

# Create a target to build all fuzzers
add_custom_target(all_fuzzers DEPENDS ${FUZZER_TARGETS})

# Create corpus directories dynamically - they already exist in the structure
# but this ensures build directory corpus structure if needed
set(CORPUS_COMMANDS "")
list(APPEND CORPUS_COMMANDS COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/corpus)
foreach(CORPUS_DIR ${CORPUS_DIRS})
    list(APPEND CORPUS_COMMANDS COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/corpus/${CORPUS_DIR})
endforeach()
list(APPEND CORPUS_COMMANDS COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/output)

add_custom_target(create_corpus_dirs ${CORPUS_COMMANDS})

# Create a target to set up the fuzzing environment
add_custom_target(setup_fuzzing
    DEPENDS all_fuzzers create_corpus_dirs
    COMMAND ${CMAKE_COMMAND} -E echo "AFL++ fuzzers built and corpus directories created"
    COMMAND ${CMAKE_COMMAND} -E echo "To run a fuzzer, use the format:"
    COMMAND ${CMAKE_COMMAND} -E echo "  ./fuzzer_name_fuzz -i corpus/corpus_name -o output/corpus_name"
    COMMAND ${CMAKE_COMMAND} -E echo "Or use the source corpus directly:"
    COMMAND ${CMAKE_COMMAND} -E echo "  ./fuzzer_name_fuzz -i ../fuzzer_name/corpus -o output/fuzzer_name"
    COMMAND ${CMAKE_COMMAND} -E echo "Run 'make usage' to see all available fuzzers"
)

# Print usage information
add_custom_target(usage
    COMMAND ${CMAKE_COMMAND} -E echo ""
    COMMAND ${CMAKE_COMMAND} -E echo "Available AFL++ fuzzers:"
)

# Add dynamic fuzzer listing to usage target
foreach(FUZZER_TARGET ${FUZZER_TARGETS})
    # Create a more readable description by converting the target name to a description
    string(REGEX REPLACE "_fuzz$" "" BASE_NAME ${FUZZER_TARGET})
    string(REPLACE "_" " " DESCRIPTION ${BASE_NAME})
    
    add_custom_command(TARGET usage POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E echo "  ${FUZZER_TARGET} - Tests ${DESCRIPTION}"
        VERBATIM
    )
endforeach()

add_custom_command(TARGET usage POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo ""
    COMMAND ${CMAKE_COMMAND} -E echo "Usage:"
    COMMAND ${CMAKE_COMMAND} -E echo "    afl-fuzz -i input_corpus_dir -o output_dir ./binary_fuzz @@"
    COMMAND ${CMAKE_COMMAND} -E echo ""
    COMMAND ${CMAKE_COMMAND} -E echo "Examples:"
    COMMAND ${CMAKE_COMMAND} -E echo "    afl-fuzz -i corpus/sha256 -o output/sha256 ./sha256_fuzz @@"
    COMMAND ${CMAKE_COMMAND} -E echo "    afl-fuzz -i ../sha256/corpus -o output/sha256 ./sha256_fuzz @@"
    VERBATIM
) 