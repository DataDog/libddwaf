#!/usr/bin/env bash

HOST_CPU=$(docker run --rm busybox uname -m)

for TARGET_CPU in x86_64 aarch64; do
    for TARGET_VERSION in '' -musl -gnu; do
        TARGET_PLATFORM="${TARGET_CPU}-linux${TARGET_VERSION}"

        echo "=============== ${HOST_CPU} => ${TARGET_PLATFORM} ====================="
        if docker build --pull --platform "linux/${HOST_CPU}" -f "docker/libddwaf/${TARGET_PLATFORM}/Dockerfile.${HOST_CPU}" -t "libddwaf-${TARGET_PLATFORM}" .; then
            echo "========= OK == ${HOST_CPU} => ${TARGET_PLATFORM} == OK ==============="

            mkdir -p tmp/build
            image_id="libddwaf-${TARGET_PLATFORM}"
            container_id=$(docker create "${image_id}")
            docker cp "${container_id}":/build "tmp/build/${TARGET_PLATFORM}"
            docker rm "${container_id}"
        else
            echo "======= FAIL == ${HOST_CPU} => ${TARGET_PLATFORM} == FAIL ============="
            exit 1
        fi
    done
done
