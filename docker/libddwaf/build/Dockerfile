FROM datadog/libddwaf:toolchain AS libddwaf_build

COPY . /libddwaf

RUN echo "Arch: $(arch), Cores: $(nproc)"

RUN ln -s /usr/lib/clang/16/lib/linux/libclang_rt.builtins-*.a /usr/lib/clang/16/lib/linux/libclang_rt.builtins.a

RUN mkdir -p /libddwaf/build
RUN cd /libddwaf/build && cmake \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_CXX_FLAGS="-stdlib=libc++ -Qunused-arguments -rtlib=compiler-rt -unwindlib=libunwind -static-libgcc -fno-omit-frame-pointer" \
    -DCMAKE_C_FLAGS="-Qunused-arguments -rtlib=compiler-rt -unwindlib=libunwind -static-libgcc -fno-omit-frame-pointer" \
    -DLIBDDWAF_BUILD_STATIC=ON \
    -DLIBDDWAF_SHARED_LINKER_FLAGS="-v -nodefaultlibs -Wl,-Bstatic -lc++ /usr/lib/clang/16/lib/linux/libclang_rt.builtins.a -lunwind -Wl,-Bdynamic -lc /usr/lib/clang/16/lib/linux/libclang_rt.builtins.a" .. && \
    ninja

RUN ninja -C /libddwaf/build validate
RUN ninja -C /libddwaf/build test

RUN patchelf --remove-needed libc.musl-$(arch).so.1 /libddwaf/build/libddwaf.so
RUN cd /libddwaf/build && ninja package && mv libddwaf-*.tar.gz libddwaf-$(arch)-linux.tar.gz
RUN tar -C /usr/lib/ -czf /libddwaf/build/libc++-static-$(arch)-linux.tar.gz libc++.a libc++experimental.a libc++abi.a libunwind.a

FROM scratch
COPY --from=libddwaf_build /libddwaf/build/*.tar.gz /
