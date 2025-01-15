ARG VERSION=unstable
# this allows to work on forked repository
ARG REPOSITORY=greenbone/gvm-libs
FROM debian:testing-slim AS build
ARG DEBIAN_FRONTEND=noninteractive

# Install
COPY . /source
RUN sh /source/.github/install-dependencies.sh
RUN cmake -DCMAKE_BUILD_TYPE=Release -B/build /source
RUN DESTDIR=/install cmake --build /build -- install

FROM debian:testing-slim

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
  apt-get install -y --no-install-recommends \
  libcjson1 \
  libcurl3t64-gnutls \
  libglib2.0-0 \
  libgnutls30 \
  libgpgme11 \
  libhiredis-dev \
  libhiredis1.1.0 \
  libldap-common \
  libnet1 \
  libpaho-mqtt1.3 \
  libpcap0.8 \
  libradcli4 \
  libssh-dev \
  libuuid1 \
  libxml2 \
  && rm -rf /var/lib/apt/lists/*

COPY --from=build /install/ /

RUN ldconfig
