FROM debian:bullseye-slim as builder

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    cmake \
    pkg-config \
    gnupg \
    libglib2.0-dev \
    libgpgme-dev \
    libgnutls28-dev \
    uuid-dev \
    libssh-gcrypt-dev \
    libhiredis-dev \
    libxml2-dev \
    libpcap-dev \
    libnet1-dev \
    libldap2-dev \
    libradcli-dev \
    libpaho-mqtt-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . /source
WORKDIR /source

RUN mkdir /build && \
    mkdir /install && \
    cd /build && \
    cmake -DCMAKE_BUILD_TYPE=Release /source && \
    make DESTDIR=/install install

FROM debian:bullseye-slim

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

COPY --from=builder /install/ /

RUN ldconfig
