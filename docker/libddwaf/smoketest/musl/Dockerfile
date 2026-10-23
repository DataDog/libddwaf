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

RUN apk --no-cache add gcc cmake make musl-dev

RUN tar -xf packages/libddwaf-*-${ARCH}-linux-*.tar.gz --strip-components=1

RUN mkdir build_static && cd build_static && \
    cmake -DCMAKE_C_FLAGS="-I/include" \
          -DLIBDDWAF_SMOKE_LINK_STATIC=ON /smoketest && \
    make && ./smoketest

RUN mkdir build_shared && cd build_shared && \
    cmake -DCMAKE_C_FLAGS="-I/include" \
          -DLIBDDWAF_SMOKE_LINK_STATIC=OFF /smoketest && \
    make && ./smoketest
