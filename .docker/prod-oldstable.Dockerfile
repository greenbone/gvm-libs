FROM debian:oldstable-slim AS build

ARG DEBIAN_FRONTEND=noninteractive

# Install
COPY . /source
RUN sh /source/.github/install-dependencies.sh /source/.github/build-dependencies.list \
  && rm -rf /var/lib/apt/lists/*
RUN cmake -DCMAKE_BUILD_TYPE=Release -DOPENVASD=0 -B/build /source \
  && DESTDIR=/install cmake --build /build -- install

FROM debian:oldstable-slim

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
  apt-get install -y --no-install-recommends \
  libcjson1 \
  libgcrypt20 \
  libglib2.0-0 \
  libgnutls30 \
  libgpgme11 \
  libhiredis0.14 \
  libldap-common \
  libnet1 \
  libpaho-mqtt1.3 \
  libpcap0.8 \
  libradcli4 \
  libssh-4 \
  libuuid1 \
  libxml2 \
  && rm -rf /var/lib/apt/lists/*

COPY --from=build /install/ /

RUN ldconfig
