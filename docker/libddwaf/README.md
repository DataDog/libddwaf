# Portable libddwaf on any Linux 2.6

This is achieved by not using the glibc which is full of extensions that
cannot be disabled and rather use the musl libc which provides this GNU Linux
portability. The musl libc is indeed a subset of the glibc, thus providing
such stricter GNU Linux >= 2.6 portability.
But the libstdc++ cannot be used witout the glibc, so we also replace
libstdc++ by LLVM's libc++. libc++ is designed to be portable to many host OS
and C libraries. It has also the nice ability to provide a static unwinding
library, which is not on glibc (libgcc_s.so only).

The resulting libddwaf and libc++ libraries are therefore able to work on
any GNU Linux distribution such as Alpine, CentOS, etc.

So the requirements to compile libddwaf and libc++ are:
  - gcc and g++ for the linux target, ideally modern-enough to compile the
    standard C++ version of libddwaf and the libc++ for it.
  - musl library headers.
