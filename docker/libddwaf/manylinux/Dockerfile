FROM quay.io/pypa/manylinux2010_x86_64 as build
ARG BUILD_TYPE="Release"

RUN yum install -y centos-release-scl
RUN /opt/python/cp310-cp310/bin/pip install cmake

WORKDIR /libddwaf
COPY . .

WORKDIR /build
RUN mkdir packages
ENV VERBOSE=1
RUN /opt/python/cp310-cp310/bin/cmake -DCMAKE_VERBOSE_MAKEFILE=1 \
    -DCMAKE_BUILD_TYPE=${BUILD_TYPE} -DLIBDDWAF_PACKAGE_SUFFIX=glibc \
    -DCMAKE_INSTALL_PREFIX=/build  -DCPACK_PACKAGE_DIRECTORY=/build/packages \
    /libddwaf

RUN /opt/python/cp310-cp310/bin/cmake --build . --target all --target testPowerWAF -j
RUN /opt/python/cp310-cp310/bin/cmake --build . --target package
RUN rm -rf packages/_CPack_Packages

ENV CTEST_OUTPUT_ON_FAILURE=1
RUN /opt/python/cp310-cp310/bin/cmake --build . --target test

FROM scratch as package-copy
COPY --from=build /build/packages/* /
