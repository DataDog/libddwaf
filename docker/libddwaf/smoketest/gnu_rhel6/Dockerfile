FROM quay.io/pypa/manylinux2010_x86_64:latest AS smoketest

ARG ARCH

COPY packages/ /packages
COPY smoketest /smoketest

RUN yum -y install gcc cmake make

RUN tar -kxf packages/libddwaf-*-${ARCH}-linux-*.tar.gz --strip-components=1
RUN ln -s /lib/libddwaf.* /lib64/

# glibc 2.12 has no aligned_alloc; libddwaf brings a hidden replacement, which
# looks up the libc one with dlsym on first use. LD_DEBUG=symbols logs that
# lookup (it fails here), so its presence proves the replacement ran.
RUN printf '%s\n' '#!/bin/sh' \
      'LD_DEBUG=symbols ./smoketest 2>&1 >/dev/null | grep -q "symbol=aligned_alloc;" && exit 0' \
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

