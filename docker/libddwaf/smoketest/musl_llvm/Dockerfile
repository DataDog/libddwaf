FROM alpine:3.18.3 AS smoketest

ARG ARCH

COPY packages/ /packages
COPY smoketest /smoketest

RUN apk --no-cache add clang cmake make musl-dev lld

RUN tar -xf packages/libddwaf-${ARCH}-linux-*.tar.gz --strip-components=1
RUN tar -C lib -xf packages/libc++-static-${ARCH}-linux-*.tar.gz

RUN mkdir build && cd build && \
    cmake -DCMAKE_C_FLAGS="-I/include" \
          -DLINK_DDWAF_STATIC=ON \
          -DLIBDDWAF_SMOKETEST_SYSROOT=/lib \
          -DCMAKE_EXE_LINKER_FLAGS="-v -fuse-ld=lld" /smoketest && \
    make && ./smoketest
