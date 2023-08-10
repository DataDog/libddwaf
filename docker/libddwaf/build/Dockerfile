FROM datadog/libddwaf:toolchain AS libddwaf_build

ARG ARCH
#-v $(pwd):/libddwaf

COPY . /libddwaf

RUN mkdir -p build
RUN cd build && cmake \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_TOOLCHAIN_FILE=/sysroot/${ARCH}-none-linux-musl/Toolchain.cmake \
    ../libddwaf && ninja
RUN patchelf --remove-needed $(basename /sysroot/${ARCH}-none-linux-musl/lib/libc.musl-*.so.1) /build/libddwaf.so

RUN ninja -C build testPowerWAF waf_validator
RUN cd libddwaf/tests && qemu-$ARCH-static /build/tests/testPowerWAF
RUN cd libddwaf/validator && qemu-$ARCH-static /build/validator/waf_validator

RUN cd /build && ninja package && mv libddwaf-*.tar.gz libddwaf-${ARCH}-linux.tar.gz
RUN tar -C /sysroot/${ARCH}-none-linux-musl/usr/lib/ -czf /build/libc++-static-${ARCH}-linux.tar.gz libc++.a libc++experimental.a libc++abi.a libunwind.a

FROM scratch
COPY --from=libddwaf_build /build/*.tar.gz /
