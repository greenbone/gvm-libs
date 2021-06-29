# gvm-libs-master-debian-buster-gcc-deploy

# Use '-slim' image for reduced image size
FROM debian:buster-slim

# Provides a Debian buster image with the core build dependencies for gvm-libs
LABEL module="gvm-libs"
LABEL branch="master"
LABEL platform="debian-buster"
LABEL compiler="gcc"
LABEL configuration="deploy"

# This will make apt-get install without question
ARG DEBIAN_FRONTEND=noninteractive

# Install core dependencies required for building gvm-libs
RUN apt-get update && apt-get install --no-install-recommends --assume-yes \
    ca-certificates \
    cmake \
    gcc \
    git \
    libglib2.0-dev \
    libgnutls28-dev \
    libgpgme-dev \
    libhiredis-dev \
    libpcap-dev \
    libssh-gcrypt-dev \
    libxml2-dev \
    libnet1-dev \
    make \
    pkg-config \
    uuid-dev \
    libssl-dev \
 && rm -rf /var/lib/apt/lists/*

# clone and install mqtt paho
# workaround otherwise paho.mqtt.c creates man1 as a file
RUN mkdir /usr/local/share/man/man1

RUN git clone --depth 1 https://github.com/eclipse/paho.mqtt.c \
 && cd paho.mqtt.c \
 && make \
 && make install \
 && cd .. \
 && rm -rf paho.mqtt.c

ENV LD_LIBRARY_PATH="/usr/local/lib"

# clone and install gvm-libs
RUN git clone --depth 1 \
    https://github.com/greenbone/gvm-libs.git \
    -b master && \
    cd gvm-libs && \
    mkdir build && \
    cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make install
