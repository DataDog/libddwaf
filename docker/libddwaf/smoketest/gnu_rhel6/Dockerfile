FROM quay.io/pypa/manylinux2010_x86_64:latest AS smoketest

ARG ARCH

COPY packages/ /packages
COPY smoketest /smoketest

RUN yum -y install gcc cmake make

RUN tar -kxf packages/libddwaf-*-${ARCH}-linux-*.tar.gz --strip-components=1
RUN ln -s /lib/libddwaf.* /lib64/

# glibc 2.12 has no aligned_alloc; libddwaf's replacement for it then
# allocates with posix_memalign. Counting those calls proves it ran.
COPY docker/libddwaf/smoketest/gnu_rhel6/count_posix_memalign.c /
RUN gcc -shared -fPIC -o /count_posix_memalign.so /count_posix_memalign.c -ldl && \
    printf '%s\n' '#!/bin/sh' \
      'LD_PRELOAD=/count_posix_memalign.so ./smoketest 2>&1 >/dev/null | grep -Eq "^posix_memalign calls: [1-9]" && exit 0' \
      'echo "aligned_alloc replacement was not exercised" >&2; exit 1' \
      > /check_aligned_alloc && chmod +x /check_aligned_alloc

RUN mkdir build_static && cd build_static && \
    cmake -DCMAKE_C_FLAGS="-I/include" \
          -DLIBDDWAF_SMOKE_LINK_STATIC=ON /smoketest && \
    make && ./smoketest && /check_aligned_alloc

RUN mkdir build_shared && cd build_shared && \
    cmake -DCMAKE_C_FLAGS="-I/include" \
          -DLIBDDWAF_SMOKE_LINK_STATIC=OFF /smoketest && \
    make && ./smoketest && /check_aligned_alloc

