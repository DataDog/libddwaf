# AFL++ Docker Image for libddwaf fuzzing
FROM ubuntu:22.04

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install basic dependencies and add LLVM repository
RUN apt-get update && apt-get install -y \
    wget \
    gnupg \
    software-properties-common \
    && wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - \
    && echo 'deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-19 main' > /etc/apt/sources.list.d/llvm-toolchain.list \
    && apt-get update

# Install system dependencies
RUN apt-get install -y \
    build-essential \
    cmake \
    git \
    curl \
    vim \
    python3 \
    python3-pip \
    llvm-19 \
    llvm-19-dev \
    llvm-19-tools \
    lcov \
    clang-19 \
    lld-19 \
    libc++-19-dev \
    libc++abi-19-dev \
    ninja-build \
    libssl-dev \
    libcurl4-openssl-dev \
    zlib1g-dev \
    xxd \
    gdb \
    linux-tools-common \
    linux-tools-generic \
    linux-tools-$(uname -r) \
    && rm -rf /var/lib/apt/lists/*

# Set up clang as default compiler
RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-19 100 && \
    update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-19 100 && \
    update-alternatives --install /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-19 100 && \
    update-alternatives --install /usr/bin/llvm-profdata llvm-profdata /usr/bin/llvm-profdata-19 100 && \
    update-alternatives --install /usr/bin/llvm-cov llvm-cov /usr/bin/llvm-cov-19 100

# Clone and build AFL++
WORKDIR /opt
RUN git config --global --add safe.directory /workspace && git clone https://github.com/AFLplusplus/AFLplusplus.git
WORKDIR /opt/AFLplusplus

# Build AFL++ with LTO support
RUN make clean && \
    make -j$(nproc) all && \
    make install

# Clone and build libddwaf
WORKDIR /opt
RUN git clone --recursive https://github.com/airbus-seclab/afl-cov-fast.git
WORKDIR /opt/afl-cov-fast
RUN pip3 install -r requirements.txt


# Set AFL++ environment variables
ENV AFL_SKIP_CPUFREQ=1
ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
ENV PATH="/opt/AFLplusplus:${PATH}"

# Create workspace directory
WORKDIR /workspace

# Copy build script
COPY build.sh /opt/build.sh
RUN chmod +x /opt/build.sh

# Create user for safer fuzzing
RUN useradd -m -s /bin/bash fuzzer && \
    chown -R fuzzer:fuzzer /workspace

# Default command
CMD ["/bin/bash"]

# Expose common AFL++ environment setup
ENV CC=afl-clang-lto
ENV CXX=afl-clang-lto++
ENV AFL_USE_ASAN=1
ENV AFL_USE_UBSAN=1 