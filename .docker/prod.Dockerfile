ARG VERSION=unstable
# this allows to work on forked repository
ARG REPOSITORY=greenbone/gvm-libs
FROM ${REPOSITORY}-build:$VERSION AS build

ARG DEBIAN_FRONTEND=noninteractive

# Install
COPY . /source
RUN cmake -DCMAKE_BUILD_TYPE=Release -B/build /source
RUN DESTDIR=/install cmake --build /build -- install 

FROM debian:stable-slim

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libglib2.0-0 \
    libgpgme11 \
    libgnutls30 \
    libuuid1 \
    libssh-gcrypt-4 \
    libhiredis0.14 \
    libxml2 \
    libpcap0.8 \
    libnet1 \
    libldap-2.4-2 \
    libradcli4 \
    libpaho-mqtt1.3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /install/ /

RUN ldconfig
