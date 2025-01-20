#/bin/sh
# This script installs the cgreen library for unit testing.

set -e

VERSION="1.6.2"
SHA256="fe6be434cbe280330420106bd5d667f1bc84ae9468960053100dbf17071036b9"

apt-get update && \
apt-get install -y --no-install-recommends  --no-install-suggests \
    build-essential \
    ca-certificates \
    cmake \
    curl \
    gcc \
    && rm -rf /var/lib/apt/lists/*

set +e

curl -sSL -o cgreen.tar.gz https://github.com/cgreen-devs/cgreen/archive/refs/tags/$VERSION.tar.gz
if [ $? -ne 0 ]; then
    echo "Error downloading cgreen"
    exit 1
fi

echo "$SHA256 cgreen.tar.gz" | sha256sum --check --status
if [ $? -ne 0 ]; then
    echo "Error validating checksum of cgreen.tar.gz"
    exit 2
fi

set -e

tar -xzf cgreen.tar.gz && cd cgreen-1.6.2
make -j$(nproc)
make install
ldconfig
