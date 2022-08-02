# Cross-compilation and portability

These Docker setups support native compilation and cross compilation. Targets architectures are named from GCC targets/Clang triplets.

Each target architecture lives in `docker/libddwaf/<target>`. In each target directory there are two Dockerfiles, one for a native `x86_64` CPU and one for a native `aarch64` CPU. When relevant, CMake `Toolchain` files are also present, one for a native `x86_64` CPU and one for a native `aarch64` CPU.

This makes producing foreign artifacts from and Intel-based CI possible. This also makes development symmetric on Intel-based machines and ARM machines (such as Apple Silicon devices).

## Quick start

Given:

- `HOST_CPU` is one of: `x86_64`, `aarch64`. In most cases use your native arch: see `docker run --rm -it busybox uname -m)`
- `TARGET_PLATFORM` is one of: `x86_64-linux`, `x86_64-linux-gnu`, `x86_64-linux-musl`, `aarch64-linux`, `aarch64-linux-gnu`, `aarch64-linux-musl`

The general usage is, using BuildKit:

```
docker buildx build --platform linux/${HOST_CPU} -f docker/libddwaf/${TARGET_PLATFORM}/Dockerfile.${HOST_CPU} -t libddwaf-${TARGET_PLATFORM} .
```

And without BuildKit:

```
docker build --pull --platform linux/${HOST_CPU} -f docker/libddwaf/${TARGET_PLATFORM}/Dockerfile.${HOST_CPU} -t libddwaf-${TARGET_PLATFORM} .
```

The non-buildkit variants are especially useful if logs get cut by buildkit log limits, and also create intermediate images that can be investigated, as opposed to BuildKit which uses a hidden cache for intermediate steps.
Note that without BuildKit will pull and tag `FROM` images, thus having them bould to the platform you picked, which may have side effects for subsequent runs that you expect to be for another platform.

Protip: always provide `--platform` to `run` and `build`, as Docker will then be able to check against that and bail out early in case of mismatch.

## Extracting artifacts from the final image

To extract data from the image:

Using BuildKit, this can be achieved using `-o`:

```
docker buildx build --platform linux/${HOST_CPU} -f docker/libddwaf/${TARGET_PLATFORM}/Dockerfile.${HOST_CPU} -t libddwaf-${TARGET_PLATFORM} -o tmp/build/${TARGET_PLATFORM} .
```

Alternatively, more generically (with or without BuildKit):

```
image_id="libddwaf-${TARGET_PLATFORM}"
container_id=$(docker create "${image_id}")
docker cp ${container_id}:/build tmp/build/${TARGET_PLATFORM}
docker rm ${container_id}
```

## Portable libddwaf on any Linux 2.6

These Docker setups support native compilation and cross compilation using Clang and a musl sysroot.

Cross-compiling is supported from both `x86_64` and `aarch64` machines:

As an example, taking `x86_64` as the native CPU, the layout is:

- `docker/libddwaf/x86_64-linux/Dockerfile.x86_64`: build a `x86_64` musl sysroot, llvm c++ libs, and libddwaf using a native `x86_64` compiler
- `docker/libddwaf/aarch64-linux/Dockerfile.x86_64`: use a cross-compiler setup to build a `aarch64` musl sysroot, llvm c++ libs, and libddwaf

Conversely, taking `aarch64` as the native CPU, the layout is:

- `docker/libddwaf/aarch64-linux/Dockerfile.aarch64`: build a `aarch64` musl sysroot, llvm c++ libs, and libddwaf using a native `aarch64` compiler
- `docker/libddwaf/x86_64-linux/Dockerfile.aarch64`: use a cross-compiler setup to build a `x86_64` musl sysroot, llvm c++ libs, and libddwaf

### How it works

This is achieved by not using GNU glibc which is full of extensions that cannot be disabled and rather use musl libc which incidently provides Linux portability.

Indeed musl libc aims to be a neutral, standard-conformant subset of glibc, thus providing such stricter Linux >= 2.6 portability.

But `libstdc++` cannot be used without glibc, so we also replace `libstdc++` by LLVM's `libc++`. `libc++` is designed to be portable to many host OS and C libraries. It has also the nice ability to provide a static unwinding library, which is not on glibc (`libgcc_s.so` only).

The resulting `libddwaf` and `libc++` libraries are therefore able to work on any Linux distribution such as Alpine, CentOS, etc.

So the requirements to compile `libddwaf` and `libc++` are:

- `gcc` and `g++` for the linux target, ideally modern-enough to compile the standard C++ version of `libddwaf` and `libc++` for it.
- musl library headers.

## Per-libc linux builds

These Docker setups support native compilation and cross compilation using GCC.

Cross-compiling is supported from both `x86_64` and `aarch64` machines:

As an example, taking `x86_64` as the native CPU, the layout is:

- `docker/libddwaf/x86_64-linux-gnu/Dockerfile.x86_64`: build against glibc using a native `x86_64` compiler
- `docker/libddwaf/x86_64-linux-musl/Dockerfile.x86_64`: build against musl using a native `x86_64` compiler
- `docker/libddwaf/aarch64-linux-gnu/Dockerfile.x86_64`: use a cross-compiler setup to build against glibc for `aarch64` on a `x86_64` machine
- `docker/libddwaf/aarch64-linux-musl/Dockerfile.x86_64`: use a cross-compiler setup to build against musl for `aarch64` on a `x86_64` machine

Conversely, taking `aarch64` as the native CPU, the layout is:

- `docker/libddwaf/aarch64-linux-gnu/Dockerfile.aarch64`: build against glibc using a native `aarch64` compiler
- `docker/libddwaf/aarch64-linux-gnu/Dockerfile.aarch64`: build against musl using a native `aarch64` compiler
- `docker/libddwaf/x86_64-linux-gnu/Dockerfile.aarch64`: use a cross-compiler setup to build against glibc for `x86_64` on a `aarch64` machine
- `docker/libddwaf/x86_64-linux-musl/Dockerfile.aarch64`: use a cross-compiler setup to build against musl for `x86_64` on a `aarch64` machine


## Testing for foreign architectures

In order to support development on both Intel and ARM (e.g Apple Silicon) machines, it is possible to test the native compilers on a foreign CPU, as one can make use of QEMU-backed CPU emulation. Note that this is much slower than cross-compiling.

On `x86_64`:

```
# enable aarch64 emulation on x86_64 (not needed on Docker for Mac)
docker run --privileged --rm tonistiigi/binfmt --install arm64
# use buildkit-based buildx
docker buildx build --platform linux/aarch64 -f docker/libddwaf/aarch64-linux/Dockerfile.aarch64 -t libddwaf-aarch64-linux .
# or use without buildkit
env DOCKER_BUILDKIT=0 docker build --pull --platform linux/aarch64 -f docker/libddwaf/aarch64-linux/Dockerfile.aarch64 -t libddwaf-aarch64-linux-gnu .
```

On `aarch64`:

```
# enable x86_64 emulation on aarch64
docker run --privileged --rm tonistiigi/binfmt --install x86_64
# use BuildKit-based buildx
docker buildx build --platform linux/x86_64 -f docker/libddwaf/x86_64-linux/Dockerfile.x86_64 -t libddwaf-x86_64-linux .
# or use without BuildKit
env DOCKER_BUILDKIT=0 docker build --pull --platform linux/x86_64 -f docker/libddwaf/x86_64-linux/Dockerfile.x86_64 -t libddwaf-x86_64-linux-gnu .
```
