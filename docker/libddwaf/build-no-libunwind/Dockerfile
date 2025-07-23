FROM datadog/libddwaf:llvm-19 AS libddwaf_build

ARG ARCH

COPY . /libddwaf

RUN mkdir -p build
RUN cd build && cmake \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_TOOLCHAIN_FILE=/libddwaf/docker/libddwaf/sysroot/Toolchain-no-libunwind.cmake.${ARCH} \
    -DLIBDDWAF_ENABLE_LTO=ON \
    -DLIBDDWAF_BUILD_SHARED=OFF \
    ../libddwaf && ninja

RUN ninja -v -C build waf_test waf_validator
RUN cd libddwaf/tests && qemu-$ARCH-static /build/tests/waf_test
RUN cd libddwaf/validator && qemu-$ARCH-static /build/validator/waf_validator

RUN cd /sysroot/${ARCH}-none-linux-musl/usr/lib/ && cp libc++.a libc++abi.a /build

# Add libc++ and relevant libraries to the archive
RUN cd /build && \
    printf "create libddwaf-combined.a\naddlib libddwaf.a\naddlib libc++.a\naddlib libc++abi.a\nsave\nend" | llvm-ar-19 -M && \
    mv libddwaf-combined.a libddwaf.a

# Strip archive
RUN cd /build && stripcmd=$(egrep -o "/usr/bin/[a-z0-9\_-]*-strip" /libddwaf/docker/libddwaf/sysroot/Toolchain-no-libunwind.cmake.${ARCH}) ; $stripcmd -x -S libddwaf.a -o libddwaf.a.stripped

RUN cd /build && ninja -v package && \
    new_name=$(ls libddwaf-*.tar.gz | head -n1 | sed -e "s/\(libddwaf-[\.0-9]*\(-\(alpha\|beta\|rc\)[0-9]\)\?\)-linux-\([_a-zA-Z0-9]*\)\(-[a-zA-Z0-9]*\)\?\.tar.gz/\1-\4-linux-musl-no-libunwind\5.tar.gz/g") ; \
    mv libddwaf-*.tar.gz "$new_name"

FROM scratch
COPY --from=libddwaf_build /build/*.tar.gz /
