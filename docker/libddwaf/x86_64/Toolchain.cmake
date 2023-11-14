set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR x86_64)
set(CMAKE_SYSROOT /muslsysroot)
set(CMAKE_AR /usr/bin/llvm-ar-11)
set(triple x86_64-none-linux-musl)
set(CMAKE_ASM_COMPILER_TARGET ${triple})
set(CMAKE_C_COMPILER /usr/bin/clang-11)
set(CMAKE_C_COMPILER_TARGET ${triple})
# compiler includes added for immintrin.h
set(c_cxx_flags "-isystem/usr/lib/llvm-11/lib/clang/11.0.1/include -resource-dir /muslsysroot/ -Qunused-arguments -rtlib=compiler-rt -unwindlib=libunwind -static-libgcc")
set(CMAKE_C_FLAGS ${c_cxx_flags})
set(CMAKE_CXX_COMPILER /usr/bin/clang++-11)
set(CMAKE_CXX_COMPILER_TARGET ${triple})
set(CMAKE_CXX_FLAGS "-stdlib=libc++ -isystem/muslsysroot/include/c++/v1 ${c_cxx_flags}")

set(linker_flags "-v -fuse-ld=lld -nodefaultlibs -Wl,-Bstatic -lc++ -lc++abi /muslsysroot/lib/linux/libclang_rt.builtins-x86_64.a -lunwind -Wl,-Bdynamic -lc /muslsysroot/lib/linux/libclang_rt.builtins-x86_64.a")
set(CMAKE_EXE_LINKER_FLAGS_INIT ${linker_flags})
set(CMAKE_SHARED_LINKER_FLAGS_INIT ${linker_flags})

set(CMAKE_NM /usr/bin/llvm-nm-11)
set(CMAKE_RANLIB /usr/bin/llvm-ranlib-11)
set(CMAKE_STRIP /usr/bin/strip) # llvm-strip-11 doesn't seem to work correctly