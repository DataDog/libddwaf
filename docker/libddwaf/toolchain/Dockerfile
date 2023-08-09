FROM debian:12.1 AS toolchain

COPY sysroot ./sysroot

# Install Dependencies
RUN apt-get update && apt-get install -y software-properties-common wget git sudo ninja-build patchelf cmake make binutils qemu-user-static file
RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -
RUN echo 'deb http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-16 main' > /etc/apt/sources.list.d/llvm-toolchain.list
RUN sudo apt-get update && sudo apt-get install -y clang-16 lld-16

# Unpack sysroots
RUN ls sysroot/
RUN for file in sysroot/*.tar.gz; do mkdir -p sysroot/$(basename $file .tar.gz) ; tar -xvzf $file -C sysroot/$(basename $file .tar.gz); rm $file; done
