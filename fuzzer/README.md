# AFL++ Fuzzing Setup

This folder contains libfuzzer harnesses with AFL++ wrapper for ease of use.

## Features

- Generic wrapper that adapts LLVMFuzzOneInput functions to work with AFL++
- Individual main functions for each fuzzing target
- Docker-based build environment with afl-clang-lto
- Support for both simple and complex fuzzing scenarios
- Easy corpus management and test case replay

## Structure

````
fuzz/
├── common/                # Common utilities and generic wrapper
│   ├── afl_wrapper.hpp    # Generic AFL++ wrapper
│   └── utils.hpp          # Common utilities
├── <fuzzer>
│   └── corpus             # Interesting seed inputs
│       ├── seed-1
│       └── seed-2
│   └── src                # Individual main entrypoint for each fuzzer
│       └── main.cpp
```

## Usage

### Building with Docker

```bash
# Build the AFL++ Docker image
cd fuzz/docker
docker build -t libddwaf-afl .

# Build all fuzzers
./scripts/build_all.sh

# Run a specific fuzzer
./scripts/run_fuzzer.sh sha256_fuzz -i corpus/sha256 -o output/sha256
````

## Adding New Fuzzers

To add a new fuzzer:

1. Create a new `*_fuzz.cpp` file in `targets/`
2. Include the generic wrapper: `#include "common/afl_wrapper.hpp"`
3. Implement your LLVMFuzzOneInput function
4. Use the `AFL_FUZZ_TARGET` macro to create the AFL++ main
5. Add the target to `CMakeLists.txt`

Example:

```cpp
#include "common/afl_wrapper.hpp"
#include "your_header.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Your fuzzing logic here
    return 0;
}

AFL_FUZZ_TARGET("your_fuzzer", LLVMFuzzerTestOneInput)
```

### Manual Building

This is not recommended, you should use the Dockerfile, available in the `./docker/` directory

```bash
# Install AFL++
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus
make && sudo make install

# Build fuzzers
mkdir build
cd build
CC=afl-clang-lto CXX=afl-clang-lto++ cmake ..
make

# Run fuzzer
afl-fuzz -i corpus/ -o output/ ./sha256_fuzz @@
```
