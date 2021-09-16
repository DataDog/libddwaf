FROM alpine:3.10 AS build
ARG BUILD_TYPE="Release"

RUN apk add --update-cache g++ bash make git libarchive libuv cmake

WORKDIR /libddwaf
COPY . .

WORKDIR /build
RUN mkdir packages
ENV VERBOSE=1
RUN cmake -DCMAKE_VERBOSE_MAKEFILE=1 -DCMAKE_BUILD_TYPE=${BUILD_TYPE}\
    -DLIBDDWAF_PACKAGE_SUFFIX=muslc -DCMAKE_INSTALL_PREFIX=/build \
    -DCPACK_PACKAGE_DIRECTORY=/build/packages /libddwaf
RUN make -j$(($(nproc) > 8 ? 8 : $(nproc))) package testPowerWAF
RUN rm -rf packages/_CPack_Packages

RUN CTEST_OUTPUT_ON_FAILURE=1 make test

FROM scratch as package-copy
COPY --from=build /build/packages/* /
