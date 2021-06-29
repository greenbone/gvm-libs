# gvm-libs-gvm-libs-20.08-debian-buster-gcc-test

# Use '-slim' image for reduced image size
FROM debian:buster-slim

# Provides a Debian buster image with the core build dependencies for gvm-libs
LABEL module="gvm-libs"
LABEL branch="gvm-libs-20.08"
LABEL platform="debian-buster"
LABEL compiler="clang"
LABEL configuration="deploy"

# This will make apt-get install without question
ARG DEBIAN_FRONTEND=noninteractive

# Install core dependencies required for building gvm-libs
RUN apt-get update && apt-get install --assume-yes \
    clang \
    clang-format \
    clang-tools \
    cmake \
    git \
    libglib2.0-dev \
    libgnutls28-dev \
    libgpgme-dev \
    libhiredis-dev \
    libpcap-dev \
    libnet1-dev \
    libssh-gcrypt-dev \
    libxml2-dev \
    pkg-config \
    uuid-dev \
    libssl-dev \
 && rm -rf /var/lib/apt/lists/*

# clone and install gvm-libs
RUN git clone --depth 1 \
    https://github.com/greenbone/gvm-libs.git \
    -b gvm-libs-20.08 && \
    cd gvm-libs && \
    mkdir build && \
    cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make install
