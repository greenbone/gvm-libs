# Dockerfile for gvm-libs-$COMPILER-build:$VERSION

# Define ARG we use through the build
ARG VERSION=unstable

# Use '-slim' image for reduced image size
FROM debian:stable-slim

# This will make apt-get install without question
ARG DEBIAN_FRONTEND=noninteractive

# Redefine ARG we use through the build
ARG COMPILER

WORKDIR /source

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
    libcgreen1-dev \
    lcov \
    && rm -rf /var/lib/apt/lists/*
