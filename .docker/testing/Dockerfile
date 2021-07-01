# Dockerfile for gvm-libs-$VERSION-$COMPILER-testing

# Define ARG we use through the build
ARG VERSION=master
ARG BUILD_TYPE=Debug
ARG COMPILER=gcc

# Use '-slim' image for reduced image size
FROM debian:buster-slim

# This will make apt-get install without question
ARG DEBIAN_FRONTEND=noninteractive

# Redefine ARG we use through the build
ARG VERSION
ARG BUILD_TYPE
ARG COMPILER

WORKDIR /usr/local/src

# Install core dependencies required for building gvm-libs
RUN apt-get update \
    && apt-get install --no-install-recommends --assume-yes \
    ca-certificates \
    cmake \
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

# Install gcc/g++ compiler
RUN if ( test "$COMPILER" = "gcc"); then \
    echo "Compiler is $COMPILER" \
    && apt-get update \
    && apt-get install --no-install-recommends --assume-yes gcc g++; \
    fi

# Install clang compiler
RUN if ( test "$COMPILER" = "clang"); then \
    echo "Compiler is $COMPILER" \
    && apt-get update \
    && apt-get install --no-install-recommends --assume-yes \
    clang \
    clang-format \
    clang-tools; \
    fi

# clone and install mqtt paho
# workaround otherwise paho.mqtt.c creates man1 as a file
RUN if ( test "$VERSION" = "master" || test "$VERSION" = "middleware" ); then \
    echo "Verion is $VERSION" \
    && mkdir /usr/local/share/man/man1 \
    && git clone --depth 1 https://github.com/eclipse/paho.mqtt.c \
    && cd paho.mqtt.c \
    && make \
    && make install \
    && cd .. \
    && rm -rf paho.mqtt.c; \
    fi

# Install Debian core dependencies required for testing gvm-libs
# support and not yet installed as dependencies of gvm-libs-core
# & install cgreen for unit tests
RUN apt-get update && \
    apt-get install --assume-yes \
    lcov \
    libical-dev \
    libpq-dev \
    libnet1-dev \
    postgresql-server-dev-all \
    xsltproc \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 https://github.com/cgreen-devs/cgreen.git \
    && cd cgreen \
    && make \
    && make test \
    && make install \
    && cd .. \
    && rm -rf cgreen

ENV LD_LIBRARY_PATH="/usr/local/lib"
