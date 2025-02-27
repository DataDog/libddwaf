FROM alpine:3.18.3 AS smoketest

ARG ARCH

COPY packages/ /packages
COPY smoketest /smoketest

RUN apk --no-cache add clang cmake make musl-dev lld

RUN tar -xf packages/libddwaf-*-${ARCH}-linux-*.tar.gz --strip-components=1

RUN mkdir build && cd build && \
    cmake -DCMAKE_C_FLAGS="-I/include" \
          -DCMAKE_C_COMPILER="/usr/bin/clang-16" \
          -DCMAKE_CXX_COMPILER="/usr/bin/clang++-16" \
          -DLIBDDWAF_SMOKE_LINK_STATIC=ON \
          -DCMAKE_EXE_LINKER_FLAGS="-v -fuse-ld=lld" /smoketest && \
    make && ./smoketest
