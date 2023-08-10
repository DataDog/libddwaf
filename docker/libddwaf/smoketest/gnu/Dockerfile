FROM debian:12.1 AS smoketest

ARG ARCH

COPY packages/ /packages
COPY smoketest /smoketest

RUN apt-get update && apt-get install -y gcc cmake make

RUN tar -kxf packages/libddwaf-${ARCH}-linux-experimental.tar.gz --strip-components=1
RUN tar -C lib -kxf packages/libc++-static-${ARCH}-linux-experimental.tar.gz

RUN mkdir build_static && cd build_static && \
    cmake -DCMAKE_C_FLAGS="-I/include" \
          -DLINK_DDWAF_STATIC=ON \
          -DLIBDDWAF_SMOKETEST_SYSROOT=/lib /smoketest && \
    make && ./smoketest

RUN mkdir build_shared && cd build_shared && \
    cmake -DCMAKE_C_FLAGS="-I/include" \
          -DLINK_DDWAF_STATIC=OFF /smoketest && \
    make && ./smoketest

