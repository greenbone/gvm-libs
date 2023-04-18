# This script installs openvas-smb-dependencies.
#/bin/sh
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
  libcgreen1-dev \
  lcov \
  && rm -rf /var/lib/apt/lists/*
