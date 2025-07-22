FROM alpine:3.21.1 AS sysroot

ARG LLVM_VERSION=19.1.7
ARG ARCH

COPY docker/libddwaf/sysroot/Toolchain.cmake.${ARCH} /Toolchain.cmake
COPY docker/libddwaf/sysroot/CHECKSUMS /CHECKSUMS

RUN echo "Building LLVM ${LLVM_VERSION} on ${ARCH}"

RUN apk --no-cache add alpine-sdk coreutils sudo bash samurai python3 linux-headers compiler-rt clang19 wget cmake make binutils musl-dev git patchelf xz lit
RUN wget https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/llvm-project-${LLVM_VERSION}.src.tar.xz && \
    grep -F llvm-project-${LLVM_VERSION}.src.tar.xz /CHECKSUMS | sha512sum --check && \
    tar -xvf llvm-project-${LLVM_VERSION}.src.tar.xz

RUN cd llvm-project-${LLVM_VERSION}.src && mkdir -p build && cd build && \
    cmake -G Ninja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DCMAKE_C_COMPILER=clang-19 \
    -DCMAKE_C_FLAGS="-fno-omit-frame-pointer -D_LIBCPP_HAS_NO_C11_ALIGNED_ALLOC=1" \
    -DCMAKE_CXX_COMPILER=clang++-19 \
    -DCMAKE_CXX_FLAGS="-fno-omit-frame-pointer -D_LIBCPP_HAS_NO_C11_ALIGNED_ALLOC=1" \
    -DLIBUNWIND_ENABLE_SHARED=OFF \
    -DLIBUNWIND_ENABLE_STATIC=ON \
    -DLIBUNWIND_USE_COMPILER_RT=ON \
    -DLIBCXXABI_ENABLE_SHARED=ON \
    -DLIBCXXABI_USE_LLVM_UNWINDER=ON \
    -DLIBCXXABI_ENABLE_STATIC_UNWINDER=ON \
    -DLIBCXXABI_USE_COMPILER_RT=ON \
    -DLIBCXX_ENABLE_SHARED=OFF \
    -DLIBCXX_HAS_MUSL_LIBC=ON \
    -DLIBCXX_USE_COMPILER_RT=ON \
    -DLIBCXX_ENABLE_STATIC_ABI_LIBRARY=ON \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi;libunwind" \
    -DLLVM_EXTERNAL_LIT=/usr/bin/lit ../runtimes && \
    ninja -v install-unwind install-cxxabi install-cxx

RUN cd /usr/lib && ln -s gcc/*/*/ resource_dir
RUN cd /usr/lib && ln -s $(find . -name 'libclang_rt.builtins-*.a' -print -quit) libclang_rt.builtins.a

RUN rm -rf /llvm-project-${LLVM_VERSION}.src
RUN rm -f llvm-project-${LLVM_VERSION}.src.tar.xz

RUN tar -czf ${ARCH}-none-linux-musl.tar.gz /usr/lib /usr/include /lib /Toolchain.cmake

FROM scratch
COPY --from=sysroot /*-none-linux-musl.tar.gz /
