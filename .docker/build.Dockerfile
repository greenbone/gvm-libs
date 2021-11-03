# Dockerfile for gvm-libs-$COMPILER-testing:$VERSION

# Define ARG we use through the build
ARG VERSION=main
ARG COMPILER=gcc

# Use '-slim' image for reduced image size
FROM debian:stable-slim

# This will make apt-get install without question
ARG DEBIAN_FRONTEND=noninteractive

# Redefine ARG we use through the build
ARG VERSION
ARG COMPILER

WORKDIR /usr/local/src

# Install core dependencies required for building and testing gvm-libs
RUN apt-get update && \
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
    && rm -rf /var/lib/apt/lists/*

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
