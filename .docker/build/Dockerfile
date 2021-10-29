# Dockerfile for gvm-libs-$VERSION-$COMPILER-build

# Define ARG we use through the build
ARG VERSION=main
ARG BUILD_TYPE=Debug
ARG COMPILER=gcc

FROM greenbone/gvm-libs-$VERSION-$COMPILER-testing

# This will make apt-get install without question
ARG DEBIAN_FRONTEND=noninteractive

# Define ARG we use through the build
ARG VERSION
ARG BUILD_TYPE
ARG COMPILER

COPY . /usr/local/src/gvm-libs
WORKDIR /usr/local/src

# clone and install gvm-libs
RUN cd gvm-libs && \
    mkdir build && \
    cd build && \
    cmake -DCMAKE_BUILD_TYPE=$BUILD_TYPE .. && \
    make install

RUN ldconfig
