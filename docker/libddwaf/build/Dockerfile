ARG MUSL_BUILD_ENV_IMAGE=docker.io/datadog/musl-build-env:1.0.5

FROM ${MUSL_BUILD_ENV_IMAGE} AS libddwaf_build

COPY . /libddwaf

RUN cmake -S /libddwaf -B /build \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_TOOLCHAIN_FILE=/usr/local/share/musl/Toolchain.cmake \
    -DLIBDDWAF_ENABLE_LTO=ON

RUN cmake --build /build --verbose --parallel $(nproc) \
    --target libddwaf_shared libddwaf_static waf_test waf_validator
RUN cd /libddwaf/tests && /build/tests/waf_test
RUN cd /libddwaf/validator && /build/validator/waf_validator

RUN cp /usr/lib/libc++.a /usr/lib/libc++abi.a /usr/lib/libunwind.a /build

# Add libc++ and relevant libraries to the archive
RUN cd /build && \
    printf "create libddwaf-combined.a\naddlib libddwaf.a\naddlib libc++.a\naddlib libc++abi.a\naddlib libunwind.a\nsave\nend" | llvm-ar -M && \
    mv libddwaf-combined.a libddwaf.a

# Strip archive
RUN strip -x -S /build/libddwaf.a -o /build/libddwaf.a.stripped

RUN cmake --build /build --verbose --parallel $(nproc) --target package && \
    cd /build && \
    new_name=$(ls libddwaf-*.tar.gz | head -n1 | sed -e "s/\(libddwaf-[\.0-9]*\(-\(alpha\|beta\|rc\)[0-9]\)\?\)-linux-\([_a-zA-Z0-9]*\)\(-[a-zA-Z0-9]*\)\?\.tar.gz/\1-\4-linux-musl\5.tar.gz/g") ; \
    mv libddwaf-*.tar.gz "$new_name"

FROM scratch
COPY --from=libddwaf_build /build/*.tar.gz /
