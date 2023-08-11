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
RUN mkdir -p build/combined_archive && cd build/combined_archive && \
        /usr/bin/llvm-ar-16 -x /build/libddwaf.a && \
        /usr/bin/llvm-ar-16 -x /sysroot/${ARCH}-none-linux-musl/usr/lib/libc++.a && \
        /usr/bin/llvm-ar-16 -x /sysroot/${ARCH}-none-linux-musl/usr/lib/libc++experimental.a && \
        /usr/bin/llvm-ar-16 -x /sysroot/${ARCH}-none-linux-musl/usr/lib/libc++abi.a && \
        /usr/bin/llvm-ar-16 -x /sysroot/${ARCH}-none-linux-musl/usr/lib/libunwind.a && \
        /usr/bin/llvm-ar-16 -qcs combined.a *.o* &&  mv combined.a ../libddwaf.a

RUN ninja -C build testPowerWAF waf_validator
RUN cd libddwaf/tests && qemu-$ARCH-static /build/tests/testPowerWAF
RUN cd libddwaf/validator && qemu-$ARCH-static /build/validator/waf_validator

RUN cd /build && ninja package && mv libddwaf-*.tar.gz libddwaf-${ARCH}-linux-musl.tar.gz
#RUN tar -C /sysroot/${ARCH}-none-linux-musl/usr/lib/ -czf /build/libc++-static-${ARCH}-linux-experimental.tar.gz libc++.a libc++experimental.a libc++abi.a libunwind.a

FROM scratch
COPY --from=libddwaf_build /build/*.tar.gz /
