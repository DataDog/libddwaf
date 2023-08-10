#!/bin/bash

declare -A platforms=(
  ["i386"]="linux/386"
  ["x86_64"]="linux/x86_64"
  ["aarch64"]="linux/arm64"
  ["armv7"]="linux/arm/v7"
)

#architectures=("i386" "x86_64" "armv7" "aarch64")
architectures=("x86_64" "aarch64")

mkdir -p sysroot

for arch in "${architectures[@]}"; do
    docker build --no-cache --progress=plain --build-arg "ARCH=$arch" --platform "${platforms[$arch]}" -f docker/libddwaf/sysroot/Dockerfile -o sysroot/ .
done

docker buildx build --platform=linux/arm64,linux/amd64 --no-cache --progress=plain -t datadog/libddwaf:toolchain -f docker/libddwaf/toolchain/Dockerfile . --push

rm -rf sysroot
