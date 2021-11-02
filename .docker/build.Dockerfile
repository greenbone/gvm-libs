# Dockerfile for gvm-libs-$COMPILER-testing:$VERSION

# Define ARG we use through the build
ARG VERSION=main
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

# Install core dependencies required for building and testing gvm-libs
RUN apt-get update && \
    apt-get install --no-install-recommends --assume-yes \
    ca-certificates \
    cmake \
    libglib2.0-dev \
    libgnutls28-dev \
    libgpgme-dev \
    libhiredis-dev \
    libpcap-dev \
    libpaho-mqtt-dev \
    libssh-gcrypt-dev \
    libxml2-dev \
    libnet1-dev \
    make \
    pkg-config \
    uuid-dev \
    libssl-dev \
    lcov \
    libical-dev \
    libpq-dev \
    postgresql-server-dev-all \
    libnet1-dev \
    xsltproc && \
    rm -rf /var/lib/apt/lists/*

# Install gcc/g++ compiler
RUN if ( test "$COMPILER" = "gcc"); then \
    echo "Compiler is $COMPILER" && \
    apt-get update && \
    apt-get install --no-install-recommends --assume-yes gcc g++; \
    fi

# Install clang compiler
RUN if ( test "$COMPILER" = "clang"); then \
    echo "Compiler is $COMPILER" && \
    apt-get update && \
    apt-get install --no-install-recommends --assume-yes \
    clang \
    clang-format \
    clang-tools; \
    fi

