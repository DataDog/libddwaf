# Using alpine image as they have a winpthreads package (pthreads port to
# win64)
FROM alpine:3.14 AS build

RUN apk --update-cache add cmake make mingw-w64-gcc mingw-w64-winpthreads git

ARG BUILD_TYPE=Release
COPY . /usr/local/src/libddwaf

RUN mkdir -p /opt/packages

RUN src=/usr/local/src/libddwaf build=$src/build; \
    cmake -DCMAKE_VERBOSE_MAKEFILE=1 -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DCMAKE_VERBOSE_MAKEFILE=1 \
          -DLIBDDWAF_BUILD_SHARED=OFF \
          -DBUILD_TESTING=OFF \
          -DCMAKE_INSTALL_PREFIX=/opt/libddwaf \
          -DCMAKE_TOOLCHAIN_FILE=/usr/local/src/libddwaf/docker/libddwaf/gcc/mingw64/x86_64-w64-mingw32.cmake \
          -DCPACK_PACKAGE_DIRECTORY=/opt/packages \
          -S $src -B $build && \
    cmake --build $build --target package

FROM scratch AS package-copy
COPY --from=build /opt/packages/* /
