set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR x86_64)
set(CMAKE_C_COMPILER /usr/bin/clang-11)
set(CMAKE_CXX_COMPILER /usr/bin/clang++-11)

set(CMAKE_AR /usr/bin/llvm-ar-11)
set(CMAKE_NM /usr/bin/llvm-nm-11)
set(CMAKE_RANLIB /usr/bin/llvm-ranlib-11)
set(CMAKE_STRIP /usr/bin/x86_64-linux-gnu-strip) # llvm-strip-11 doesn't seem to work correctly

set(triple x86_64-none-linux-musl)
set(CMAKE_ASM_COMPILER_TARGET ${triple})
set(CMAKE_C_COMPILER_TARGET ${triple})

set(CMAKE_SYSROOT /sysroot/musl)
set(c_cxx_flags "-resource-dir /sysroot/musl -Qunused-arguments -rtlib=compiler-rt -unwindlib=libunwind -static-libgcc")
set(CMAKE_C_FLAGS ${c_cxx_flags})
set(CMAKE_CXX_COMPILER_TARGET ${triple})
set(CMAKE_CXX_FLAGS "-stdlib=libc++ -isystem/sysroot/musl/include/c++/v1 ${c_cxx_flags}")

set(linker_flags "-v -fuse-ld=lld -nodefaultlibs -Wl,-Bstatic -lc++ -lc++abi /sysroot/musl/lib/linux/libclang_rt.builtins-x86_64.a -lunwind -Wl,-Bdynamic -lc /sysroot/musl/lib/linux/libclang_rt.builtins-x86_64.a")
set(CMAKE_EXE_LINKER_FLAGS_INIT ${linker_flags})
set(CMAKE_SHARED_LINKER_FLAGS_INIT ${linker_flags})


