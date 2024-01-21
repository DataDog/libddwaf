FROM datadog/libddwaf:toolchain AS libddwaf_build

ARG ARCH

COPY . /libddwaf

RUN wget https://sh.rustup.rs -O rustup.sh && chmod u+x rustup.sh && ./rustup.sh -y -t x86_64-unknown-linux-musl aarch64-unknown-linux-musl armv7-unknown-linux-musleabihf i386-unknown-linux-musl
RUN ls /root/.cargo/bin | xargs bash -c 'echo "Linking $0" ; ln -s /root/.cargo/bin/$0 /usr/bin/$0'

RUN mkdir -p build
RUN cd build && cmake \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_TOOLCHAIN_FILE=/libddwaf/docker/libddwaf/sysroot/Toolchain.cmake.${ARCH} \
    -DLIBDDWAF_ENABLE_LTO=ON \
    ../libddwaf && ninja
RUN patchelf --remove-needed $(basename /sysroot/${ARCH}-none-linux-musl/lib/libc.musl-*.so.1) /build/libddwaf.so

RUN ninja -v -C build waf_test waf_validator
RUN cd libddwaf/tests && qemu-$ARCH-static /build/tests/waf_test
RUN cd libddwaf/validator && qemu-$ARCH-static /build/validator/waf_validator

RUN cd /sysroot/${ARCH}-none-linux-musl/usr/lib/ && cp libc++.a libc++abi.a libunwind.a /build

# Add libc++ and relevant libraries to the archive
RUN cd /build && \
    printf "create libddwaf-combined.a\naddlib libddwaf.a\naddlib libc++.a\naddlib libc++abi.a\naddlib libunwind.a\nsave\nend" | llvm-ar-16 -M && \
    mv libddwaf-combined.a libddwaf.a

# Strip archive
RUN cd /build && stripcmd=$(egrep -o "/usr/bin/[a-z0-9\_-]*-strip" /libddwaf/docker/libddwaf/sysroot/Toolchain.cmake.${ARCH}) ; $stripcmd -x -S libddwaf.a -o libddwaf.a.stripped

RUN cd /build && ninja -v package && \
    new_name=$(ls libddwaf-*.tar.gz | head -n1 | sed "s/\(libddwaf-[\.0-9]*\)-linux-\([_a-zA-Z0-9]*\)\(-\?[a-zA-Z0-9]*.tar.gz\)/\1-\2-linux-musl\3/g") ; \
    mv libddwaf-*.tar.gz "$new_name"

FROM scratch
COPY --from=libddwaf_build /build/*.tar.gz /
