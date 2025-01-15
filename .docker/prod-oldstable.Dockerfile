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
  cmake \
  curl \
  gnupg \
  lcov \
  libcgreen1-dev \
  libcjson-dev \
  libglib2.0-dev \
  libgnutls28-dev \
  libgpgme-dev \
  libhiredis-dev \
  libldap2-dev \
  libnet1-dev \
  libpaho-mqtt-dev \
  libpcap-dev \
  libradcli-dev \
  libssh-gcrypt-dev \
  libxml2-dev \
  pkg-config \
  uuid-dev \
  && rm -rf /var/lib/apt/lists/*
RUN cmake -DCMAKE_BUILD_TYPE=Release -DOPENVASD=0 -B/build /source
RUN DESTDIR=/install cmake --build /build -- install

FROM debian:oldstable-slim

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
  apt-get install -y --no-install-recommends \
  libcjson1 \
  libglib2.0-0 \
  libgnutls30 \
  libgpgme11 \
  libhiredis0.14 \
  libjson-glib-1.0-0 \
  libldap-common \
  libnet1 \
  libpaho-mqtt1.3 \
  libpcap0.8 \
  libradcli4 \
  libssh-gcrypt-4 \
  libuuid1 \
  libxml2 \
  && rm -rf /var/lib/apt/lists/*

COPY --from=build /install/ /

RUN ldconfig
