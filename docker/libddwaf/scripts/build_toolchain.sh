#!/bin/bash
set -eu

declare -A platforms=(
  ["i386"]="linux/386"
  ["x86_64"]="linux/x86_64"
  ["aarch64"]="linux/arm64"
  ["armv7"]="linux/arm/v7"
)

mkdir -p sysroot

for arch in "${!platforms[@]}"; do
    docker build --no-cache --progress=plain --build-arg "ARCH=$arch" --platform "${platforms[$arch]}" -f docker/libddwaf/sysroot/Dockerfile -o sysroot/ .
done

docker buildx build --platform=linux/arm64,linux/amd64 --no-cache --progress=plain -t datadog/libddwaf:llvm-19 -f docker/libddwaf/toolchain/Dockerfile . --push

rm -rf sysroot
