#!/bin/sh
# This script installs openvas-smb-dependencies.
set -ex
apt-get update && \
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
  lcov \
  && rm -rf /var/lib/apt/lists/*


curl -L -o cgreen.tar.gz https://github.com/cgreen-devs/cgreen/archive/refs/tags/1.6.2.tar.gz -k
tar -xzf cgreen.tar.gz && cd cgreen-1.6.2
make install
ldconfig
