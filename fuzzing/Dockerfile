FROM ubuntu:focal

RUN apt-get -y update && apt-get -y upgrade

# Python 3, Make, CMake >= 3.16, git, clang, libFuzzer
RUN DEBIAN_FRONTEND="noninteractive" apt-get -y install python3 apt-transport-https build-essential wget cmake git clang libfuzzer-10-dev

# Check versions
RUN python3 --version \
    && make --version \
    && cmake --version \
    && clang --version \
    && git --version

COPY . /libddwaf
WORKDIR /libddwaf

RUN ./fuzzing/build.sh
