ARG MANYLINUX_ARCH=x86_64
FROM quay.io/pypa/manylinux2010_${MANYLINUX_ARCH}:latest AS smoketest

ARG ARCH

COPY packages/ /packages
COPY smoketest /smoketest

RUN yum -y install gcc cmake make

RUN tar -kxf packages/libddwaf-*-${ARCH}-linux-*.tar.gz --strip-components=1
RUN ln -s /lib/libddwaf.* /lib64/

RUN mkdir build_static && cd build_static && \
    cmake -DCMAKE_C_FLAGS="-I/include" \
          -DLIBDDWAF_SMOKE_LINK_STATIC=ON /smoketest && \
    make && ./smoketest

RUN mkdir build_shared && cd build_shared && \
    cmake -DCMAKE_C_FLAGS="-I/include" \
          -DLIBDDWAF_SMOKE_LINK_STATIC=OFF /smoketest && \
    make && ./smoketest

