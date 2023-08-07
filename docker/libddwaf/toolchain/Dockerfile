FROM alpine:latest AS toolchain

RUN apk --no-cache add alpine-sdk coreutils sudo bash samurai python3 linux-headers compiler-rt clang wget cmake make binutils musl-dev git patchelf xz lit
RUN wget https://github.com/llvm/llvm-project/releases/download/llvmorg-16.0.6/llvm-project-16.0.6.src.tar.xz && \
    tar -xvf llvm-project-16.0.6.src.tar.xz

RUN cd llvm-project-16.0.6.src && mkdir -p build && cd build && \
    cmake -G Ninja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_C_FLAGS=-fno-omit-frame-pointer \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_CXX_FLAGS=-fno-omit-frame-pointer \
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
    -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi;libunwind" \
    -DLLVM_EXTERNAL_LIT=/usr/bin/lit ../runtimes && \
    ninja install-unwind install-cxxabi install-cxx

RUN rm -rf /llvm-project-16.0.6.src
RUN rm -f llvm-project-16.0.6.src.tar.xz
