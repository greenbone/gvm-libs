ARG VERSION=unstable
# this allows to work on forked repository
ARG REPOSITORY=greenbone/gvm-libs
FROM debian:oldstable-slim AS build
ARG DEBIAN_FRONTEND=noninteractive

# Install
COPY . /source
RUN apt-get update && \
  apt-get install -y --no-install-recommends \
  build-essential \
  curl \
  cmake \
  pkg-config \
  gnupg \
  libcjson-dev \
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
  libcgreen1-dev \
  lcov \
  && rm -rf /var/lib/apt/lists/*
RUN cmake -DCMAKE_BUILD_TYPE=Release -B/build /source
RUN DESTDIR=/install cmake --build /build -- install

FROM debian:oldstable-slim

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
  libldap-common \
  libradcli4 \
  libpaho-mqtt1.3 \
  && rm -rf /var/lib/apt/lists/*

COPY --from=build /install/ /

RUN ldconfig
