FROM alpine:3.18.3 AS smoketest_musl_shared

ARG ARCH

COPY /tmp/packages/ /packages
COPY smoketest /smoketest

RUN apk --no-cache add gcc cmake make musl-dev

RUN tar -xf packages/libddwaf-${ARCH}-linux.tar.gz --strip-components=1
RUN tar -C lib -xf packages/libc++-static-${ARCH}-linux.tar.gz

RUN mkdir build && cd build && \
    cmake -DCMAKE_C_FLAGS="-I/include" \
          -DLINK_DDWAF_STATIC=OFF /smoketest && make

RUN /build/smoketest

