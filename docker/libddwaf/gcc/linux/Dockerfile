# Multi-Stage Dockerfile allowing to generate libddwaf.a portable on any
# GNU Linux >= 2.6.
# This is achieved by not using the glibc which is full of extensions that
# cannot be disabled and rather use the musl libc which provides this GNU Linux
# portability. The musl libc is indeed a subset of the glibc, thus providing
# such stricter GNU Linux >= 2.6 portability.
# But the libstdc++ cannot be used witout the glibc, so we also replace
# libstdc++ by LLVM's libc++. libc++ is designed to be portable to many host OS
# and C libraries. It has also the nice ability to provide a static unwinding
# library, which is not on glibc (libgcc_s.so only).
#
# The resulting libddwaf and libc++ libraries are therefore able to work on
# any GNU Linux distribution such as Alpine, CentOS, etc.
#
# So the requirements to compile libddwaf and libc++ are:
#   - gcc and g++ for the linux target, ideally modern-enough to compile the
#     standard C++ version of libddwaf and the libc++ for it.
#   - musl library headers.
#
# The 'gcc' docker image, based on debian, therefore meets these requirements
# but is also available on multiple platform. This offers the possibility to
# build this dockerfile using multi-platfrom docker build using
# `docker buildx build --platform=<targets> -f <Dockerfile> <context>`.

FROM gcc:9 AS base

# Target-specific settings such as CFLAGS
# Technique taken from https://github.com/docker/buildx/issues/157
FROM base AS base-amd64
# Specific CFLAGS:
#   - `-Wa,-mrelax-relocations=no`: required by old gcc toolchains that do not
#     support this type of relocation.
ENV TARGET_CMAKE_C_FLAGS "-Wa,-mrelax-relocations=no"

FROM base AS base-arm64
ENV TARGET_CMAKE_C_FLAGS ""

ARG TARGETARCH
FROM base-$TARGETARCH AS libcxx-dev

# - curl to download LLVM tarballs
# - cmake and make to build
# - python is needed by libc++'s build
# - musl-dev to reuse the pre-compiled musl library from debian
RUN echo "deb http://ftp.debian.org/debian buster-backports main" > /etc/apt/sources.list.d/backports.list
RUN apt update && apt install -y curl make python musl-dev
RUN apt -t buster-backports install -y cmake

ENV prefix=/opt
ENV libcxx_prefix=$prefix/libc++
ENV src_prefix=/usr/local/src
ENV libcxx_src_prefix=$src_prefix/libc++

ENV llvm_src=$libcxx_src_prefix/llvm
ENV libunwind_src=$libcxx_src_prefix/libunwind
ENV libcxxabi_src=$libcxx_src_prefix/libcxxabi
ENV libcxx_src=$libcxx_src_prefix/libcxx

# Download libc++ libraries
# Note: the last version of libc++ 9.0.0 gives compilation error
ARG LIBCXX_VERSION=8.0.1
RUN src_baseurl=https://github.com/llvm/llvm-project/releases/download/llvmorg-$LIBCXX_VERSION; \
    llvm_src_url=$src_baseurl/llvm-$LIBCXX_VERSION.src.tar.xz; \
    libcxx_src_url=$src_baseurl/libcxx-$LIBCXX_VERSION.src.tar.xz; \
    libcxxabi_src_url=$src_baseurl/libcxxabi-$LIBCXX_VERSION.src.tar.xz; \
    libunwind_src_url=$src_baseurl/libunwind-$LIBCXX_VERSION.src.tar.xz; \
    mkdir -p $llvm_src $libcxx_src $libcxxabi_src $libunwind_src; \
    curl -sSL $libcxx_src_url | tar --strip-components=1 -xJC $libcxx_src; \
    curl -sSL $libcxxabi_src_url | tar --strip-components=1 -xJC $libcxxabi_src; \
    curl -sSL $libunwind_src_url | tar --strip-components=1 -xJC $libunwind_src; \
    curl -sSL $llvm_src_url | tar --strip-components=1 -xJC $llvm_src

ARG BUILD_TYPE=Release
# Common CFLAGS:
#   - `-nostdinc`: we want to use the musl libc headers. The path to musl
#     will be added in the following RUN commands as they cannot be
ENV COMMON_CMAKE_C_FLAGS="-nostdinc $TARGET_CMAKE_C_FLAGS"
# Common CXXFLAGS: same as CFLAGS so far
ENV COMMON_CMAKE_CXX_FLAGS="$COMMON_CMAKE_C_FLAGS"
# Common CMake options
ENV COMMON_CMAKE_OPTS="-v -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DCMAKE_VERBOSE_MAKEFILE=1"
# Common options of libc++ libraries only
ENV LIBCXX_COMMON_CMAKE_OPTS="$COMMON_CMAKE_OPTS -DCMAKE_INSTALL_PREFIX=$libcxx_prefix"

# Include search path for standard C and C++ headers:
#  - STDINC: path to the custom standard C library headers. Note that it
#    contains a subcommand that is not evaluated by ENV (ENV limitation for
#    now).
#  - STDINCXX: path to the libc++ headers.
# (Dockerfile limitation).
ENV LIBC_TRIPLET="$(uname -m)-linux-musl"
ENV STDINC="-isystem /usr/include/$LIBC_TRIPLET"
ENV STDLIB="-L/usr/lib/$LIBC_TRIPLET"
ENV STDINCXX="-isystem $libcxx_prefix/include/c++/v1"

# Build container ready - print every environment variable for the record
RUN env

# libunwind to replace libgcc_s.so
RUN src=$libunwind_src build=$src/build stdinc=$(eval echo $STDINC); \
    cmake $LIBCXX_COMMON_CMAKE_OPTS \
          -DLIBUNWIND_ENABLE_SHARED=0 \
          -DLLVM_PATH=$llvm_src \
          -DCMAKE_C_FLAGS="$COMMON_CMAKE_C_FLAGS $stdinc" \
          -DCMAKE_CXX_FLAGS="$COMMON_CMAKE_CXX_FLAGS -D_LIBUNWIND_USE_DLADDR=0 $stdinc" \
          -S $src -B $build && \
    cmake --build $build -j $(($(nproc) > 8 ? 8 : $(nproc))) --target install

# libc++abi using libunwind
RUN src=$libcxxabi_src build=$src/build stdinc=$(eval echo $STDINC); \
    cmake $LIBCXX_COMMON_CMAKE_OPTS \
          -DLIBCXXABI_ENABLE_SHARED=0 \
          -DLLVM_PATH=$llvm_src \
          -DLIBCXXABI_LIBUNWIND_PATH=$libunwind_src \
          -DLIBCXXABI_LIBCXX_INCLUDES=$libcxx_src/include \
          -DLIBCXXABI_USE_LLVM_UNWINDER=1 \
          -DCMAKE_CXX_FLAGS="$COMMON_CMAKE_CXX_FLAGS $stdinc" \
          -S $src -B $build && \
    cmake --build $build -j $(($(nproc) > 8 ? 8 : $(nproc))) --target install

# libc++ using the libc++abi
RUN src=$libcxx_src build=$src/build stdinc=$(eval echo $STDINC); \
    cmake $LIBCXX_COMMON_CMAKE_OPTS \
          -DLIBCXX_ENABLE_SHARED=0 \
          -DLLVM_PATH=$llvm_src \
          -DLIBCXX_ENABLE_FILESYSTEM=0 \
          -DLIBCXX_ENABLE_EXPERIMENTAL_LIBRARY=0 \
          -DLIBCXX_HAS_MUSL_LIBC=1 \
          -DLIBCXX_HAS_GCC_S_LIB=0 \
          -DLIBCXX_CXX_ABI=libcxxabi \
          -DLIBCXX_CXX_ABI_INCLUDE_PATHS=$libcxxabi_src/include \
          -DLIBCXX_CXX_ABI_LIBRARY_PATH=$libcxx_prefix/lib \
          -DCMAKE_CXX_FLAGS="$COMMON_CMAKE_CXX_FLAGS $stdinc" \
          -S $src -B $build && \
    cmake --build $build -j $(($(nproc) > 8 ? 8 : $(nproc))) --target install

FROM libcxx-dev AS libddwaf-dev
ENV libddwaf_src=$src_prefix/libddwaf
ENV libddwaf_prefix=$prefix/libddwaf
ENV packages_prefix=$prefix/packages
COPY . $libddwaf_src

# libddwaf.a using the libc++
# te that stdinc needs to be after stdinc++ because of C++ header wrappers
# (ie. usage of #include_next).
RUN src=$libddwaf_src build=$src/build stdinc=$(eval echo $STDINC); stdlib=$(eval echo $STDLIB); \
    cmake $COMMON_CMAKE_OPTS \
          -DCMAKE_C_FLAGS="$COMMON_CMAKE_C_FLAGS $stdinc" \
          -DCMAKE_CXX_FLAGS="$COMMON_CMAKE_CXX_FLAGS -nostdinc++ $STDINCXX $stdinc" \
          -DCMAKE_INSTALL_PREFIX=$libddwaf_prefix \
          -DCPACK_PACKAGE_DIRECTORY=$packages_prefix \
          -DLIBDDWAF_SHARED_LINKER_FLAGS="-nodefaultlibs -L$libcxx_prefix/lib -lc++ -lc++abi -lunwind $stdlib -l:libc.a -lm -lgcc" \
          -DLIBDDWAF_EXE_LINKER_FLAGS="-nodefaultlibs -L$libcxx_prefix/lib -lc++ -lc++abi -lunwind $stdlib -l:libc.a -lm -lgcc" \
          -DLIBDDWAF_PACKAGE_SUFFIX=static \
          -DLIBDDWAF_BUILD_SHARED=OFF \
          -DBUILD_TESTING=OFF \
          -S $src -B $build && \
    cmake --build $build -j $(($(nproc) > 8 ? 8 : $(nproc))) --target package && \
    rm -rf $packages_prefix/_CPack_Packages

# libc++ tarball
RUN tar -C $libcxx_prefix/../ -czf $packages_prefix/libc++.tar.gz $(basename $libcxx_prefix)

# Final stage only with artefacts
FROM scratch AS package-copy
COPY --from=libddwaf-dev /opt /opt
