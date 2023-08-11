FROM datadog/libddwaf:toolchain AS libddwaf_build

ARG ARCH

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

RUN cd /sysroot/${ARCH}-none-linux-musl/usr/lib/ && cp libc++.a libc++abi.a libunwind.a /build

# Add libc++ and relevant libraries to the archive
RUN cd /build && \
    printf "create libddwaf-combined.a\naddlib libddwaf.a\naddlib libc++.a\naddlib libc++abi.a\naddlib libunwind.a\nsave\nend" | llvm-ar-16 -M && \
    mv libddwaf-combined.a libddwaf.a

# Strip archive
RUN cd /build && stripcmd=$(egrep -o "/usr/bin/[a-z0-9\_-]*-strip" /sysroot/${ARCH}-none-linux-musl/Toolchain.cmake) ; $stripcmd -x -S libddwaf.a -o libddwaf.a.stripped

RUN cd /build && ninja package && mv libddwaf-*.tar.gz libddwaf-${ARCH}-linux-musl.tar.gz

FROM scratch
COPY --from=libddwaf_build /build/*.tar.gz /
