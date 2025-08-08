# AFL++ Fuzzing Setup

This folder contains `libfuzzer` harnesses with [AFL++](https://github.com/AFLplusplus/AFLplusplus/) wrapper for ease of use.

## Structure

```
fuzz/
├── common/                # Common utilities and generic wrapper
│   ├── afl_wrapper.hpp    # Generic AFL++ wrapper
│   └── utils.hpp          # Common utilities
├── docker/                # The dockerfile and script used to run the fuzzer easily
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
```

### Running the fuzzer in docker

```bash
# The added capabilities are useful to run GDB, but also perform kernel setting tweaks
docker run --privileged --cap-add=SYS_PTRACE --cap-add=SYS_ADMIN --security-opt seccomp=unconfined -v $(pwd):/workspace -it libddwaf-afl

# Build all fuzzers
./fuzzer/docker/build.sh

# Run all fuzzer
./fuzzer/docker/run_fuzzers.sh

# Run a single fuzzer
./fuzzer/docker/run_fuzzers.sh e2e

# Once you are done, you may want to minimize the corpus to sync it back in git
./fuzzer/docker/minimize_corpus.sh
```

## Adding New Fuzzers

To add a new fuzzer:

- Create a new folder in `/fuzzer/`, with a `src` and `corpus` directory.
  - in `src`, put a main.cpp following the other files templates
  - in corpus, add a `.gitkeep` file and at least a single file.
- run `./fuzzer/docker/build.sh`
- run `./fuzzer/docker/run_fuzzers.sh MY_NEW_FUZZER_NAME`

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

### Out of Docker fuzzer build

You may need to follow AFL++ installation instruction to get the lastest dependencies.
It's likely you simply want to use Dockerfile mentioned above, available in the `./docker/` directory

```bash
# Install AFL++
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus
make && sudo make install

# Build fuzzers
mkdir fuzzer/build
cd fuzzer/build
CC=afl-clang-lto CXX=afl-clang-lto++ cmake ..
make

# Run fuzzer (change the corpus and output to the correct path)
afl-fuzz -i corpus/ -o output/ ./sha256_fuzz
```
