#!/bin/sh
# This script installs openvas-smb-dependencies.
set -ex
apt-get update && \
  apt-get install -y --no-install-recommends \
  build-essential \
  cmake \
  curl \
  gnupg \
  lcov \
  libcjson-dev \
  libcurl4-openssl-dev \
  libgcrypt-dev \
  libglib2.0-dev \
  libgnutls28-dev \
  libgpgme-dev \
  libhiredis-dev \
  libldap2-dev \
  libnet1-dev \
  libpaho-mqtt-dev \
  libpcap-dev \
  libradcli-dev \
  libssh-dev \
  libxml2-dev \
  pkg-config \
  uuid-dev \
  && rm -rf /var/lib/apt/lists/*


curl -L -o cgreen.tar.gz https://github.com/cgreen-devs/cgreen/archive/refs/tags/1.6.2.tar.gz -k
tar -xzf cgreen.tar.gz && cd cgreen-1.6.2
make install
ldconfig
