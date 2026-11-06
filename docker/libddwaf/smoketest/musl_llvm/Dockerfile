FROM alpine:3.18.3 AS truststore

RUN apk add --no-cache ca-certificates && \
    sed -i -e 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt|!&|' \
           -e 's|^mozilla/Comodo_AAA_Services_root.crt|!&|' /etc/ca-certificates.conf && \
    rm -f /usr/share/ca-certificates/mozilla/emSign_ECC_Root_CA_-_G3.crt \
          /usr/share/ca-certificates/mozilla/Comodo_AAA_Services_root.crt && \
    update-ca-certificates -f

FROM truststore AS smoketest

ARG ARCH

COPY packages/ /packages
COPY smoketest /smoketest

RUN apk --no-cache add clang cmake make musl-dev lld

RUN tar -xf packages/libddwaf-*-${ARCH}-linux-*.tar.gz --strip-components=1

RUN mkdir build && cd build && \
    cmake -DCMAKE_C_FLAGS="-I/include" \
          -DCMAKE_C_COMPILER="/usr/bin/clang-16" \
          -DCMAKE_CXX_COMPILER="/usr/bin/clang++-16" \
          -DLIBDDWAF_SMOKE_LINK_STATIC=ON \
          -DCMAKE_EXE_LINKER_FLAGS="-v -fuse-ld=lld" /smoketest && \
    make && ./smoketest
