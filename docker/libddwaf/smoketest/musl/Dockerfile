FROM alpine:3.18.3 AS smoketest

ARG ARCH

COPY packages/ /packages
COPY smoketest /smoketest

RUN apk --no-cache add gcc cmake make musl-dev

RUN tar -xf packages/libddwaf-${ARCH}-linux-*.tar.gz --strip-components=1
RUN tar -C lib -xf packages/libc++-static-${ARCH}-linux-*.tar.gz

RUN mkdir build_static && cd build_static && \
    cmake -DCMAKE_C_FLAGS="-I/include" \
          -DLINK_DDWAF_STATIC=ON \
          -DLIBDDWAF_SMOKETEST_SYSROOT=/lib /smoketest && \
    make && ./smoketest

RUN mkdir build_shared && cd build_shared && \
    cmake -DCMAKE_C_FLAGS="-I/include" \
          -DLINK_DDWAF_STATIC=OFF /smoketest && \
    make && ./smoketest
