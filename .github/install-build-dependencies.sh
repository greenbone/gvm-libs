#!/bin/sh
# This script installs gvm-libs dependencies
set -ex

apt-get update && \
apt-get install -y --no-install-recommends  --no-install-suggests \
  build-essential \
  cmake \
  curl \
  gnupg \
  lcov \
  libcjson-dev \
  libcurl4-gnutls-dev \
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
