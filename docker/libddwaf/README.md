# Cross-compilation and portability

## Portable libddwaf on any Linux 2.6

This is achieved by not using GNU glibc which is full of extensions that cannot be disabled and rather use the musl libc which provides this GNU Linux portability.

musl libc indeed aims to be a neutral subset of glibc, thus providing such stricter GNU Linux >= 2.6 portability.

But `libstdc++` cannot be used without glibc, so we also replace `libstdc++` by LLVM's `libc++`. `libc++` is designed to be portable to many host OS and C libraries. It has also the nice ability to provide a static unwinding library, which is not on glibc (`libgcc_s.so` only).

The resulting `libddwaf` and `libc++` libraries are therefore able to work on any GNU Linux distribution such as Alpine, CentOS, etc.

So the requirements to compile `libddwaf` and `libc++` are:

- `gcc` and `g++` for the linux target, ideally modern-enough to compile the standard C++ version of `libddwaf` and `libc++` for it.
- musl library headers.

Cross-compiling is supported from `x86_64` machines:

- `x86_64` builds are produced natively. See `docker/libddwaf/x86_64`.
- `aarch64` builds are produced via cross-compiling on `x86_64`. See `docker/libddwaf/aarch64`.

The setups in `docker/libddwaf/aarch64` and `docker/libddwaf/x86_64` do not currently support development on ARM machines (e.g Apple Silicon).

## Per-libc linux builds

These Docker setups support native compilation and cross compilation. Targets architectures are named from GCC targets/Clang triplets.

Each target architecture lives in `docker/libddwaf/<target>`. In each target directory there are two Dockerfiles, one for a native `x86_64` CPU and one for a native `aarch64` CPU.

As an example, taking `x86_64` as the native CPU, the layout is:

- `docker/libddwaf/x86_64-linux-gnu/Dockerfile.x86_64`: build against glibc using a native `x86_64` compiler
- `docker/libddwaf/x86_64-linux-musl/Dockerfile.x86_64`: build against musl using a native `x86_64` compiler
- `docker/libddwaf/aarch64-linux-gnu/Dockerfile.x86_64`: use a cross-compiler setup to build against glibc for `aarch64` on a `x86_64` machine
- `docker/libddwaf/aarch64-linux-gnu/Dockerfile.x86_64`: use a cross-compiler setup to build against glibc for `aarch64` on a `x86_64` machine

Conversely, talking `aarch64` as the native CPU, the layout is:

- `docker/libddwaf/aarch64-linux-gnu/Dockerfile.aarch64`: build against glibc using a native `aarch64` compiler
- `docker/libddwaf/aarch64-linux-gnu/Dockerfile.aarch64`: build against musl using a native `aarch64` compiler
- `docker/libddwaf/x86_64-linux-gnu/Dockerfile.aarch64`: use a cross-compiler setup to build against glibc for `x86_64` on a `aarch64` machine
- `docker/libddwaf/x86_64-linux-musl/Dockerfile.aarch64`: use a cross-compiler setup to build against glibc for `x86_64` on a `aarch64` machine

In order to support development on both Intel and ARM (e.g Apple Silicon) machines, it is possible to test the native compilers on a foreign CPU, as one can make use of QEMU-backed CPU emulation. Note that this is much slower than cross-compiling.

On `x86_64`:

```
# enable aarch64 emulation on x86_64 (not needed on Docker for Mac)
docker run --privileged --rm tonistiigi/binfmt --install arm64
# use buildkit-based buildx
docker buildx build --platform linux/aarch64 -f docker/libddwaf/aarch64-linux-gnu/Dockerfile.aarch64 .
# or use without buildkit
env DOCKER_BUILDKIT=0 docker build --platform linux/aarch64 -f docker/libddwaf/aarch64-linux-gnu/Dockerfile.aarch64 .
```

On `aarch64`:

```
# enable x86_64 emulation on aarch64
docker run --privileged --rm tonistiigi/binfmt --install x86_64
# use BuildKit-based buildx
docker buildx build --platform linux/x86_64 -f docker/libddwaf/x86_64-linux-gnu/Dockerfile.x86_64 .
# or use without BuildKit
env DOCKER_BUILDKIT=0 docker build --platform linux/x86_64 -f docker/libddwaf/x86_64-linux-gnu/Dockerfile.x86_64 .
```

The non-buildkit variants are especially useful if logs get cut by buildkit log limits, and also create intermediate images that can be investigated, as opposed to BuildKit which uses a hidden cache for intermediate steps. Note that without BuildKit will pull and tag `FROM` images, thus having them bould to the platform you picked, which may have side effects for subsequent runs that you expect to be for another platform. Protip: always provide `--platform` to `run` and `build`, as Docker will then be able to check against that and bail out in case of mismatch.

To extract data from the image:

```
docker build --platform linux/x86_64 -f docker/libddwaf/x86_64-linux-gnu/Dockerfile.x86_64 .
container=$(docker create <image id>)
docker cp ${container}:/build tmp/build/x86_64-linux-gnu
docker rm ${container}
```
