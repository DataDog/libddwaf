FROM debian:12.1 AS smoketest

ARG ARCH

COPY packages/ /packages
COPY smoketest /smoketest

RUN apt-get update && apt-get install -y gcc cmake make

RUN tar -kxf packages/libddwaf-${ARCH}-linux-*.tar.gz --strip-components=1

RUN mkdir build_static && cd build_static && \
    cmake -DCMAKE_C_FLAGS="-I/include" \
          -DLIBDDWAF_SMOKE_LINK_STATIC=ON /smoketest && \
    make && ./smoketest

RUN mkdir build_shared && cd build_shared && \
    cmake -DCMAKE_C_FLAGS="-I/include" \
          -DLIBDDWAF_SMOKE_LINK_STATIC=OFF /smoketest && \
    make && ./smoketest

