#!/bin/sh
# This script installs gvm-libs dependencies
set -e

BASEDIR=$(dirname $0)
DEFAULT_DEPENDENCIES_FILE="$BASEDIR/build-dependencies.list"
DEPENDENCIES_FILE=${1:-$DEFAULT_DEPENDENCIES_FILE}

apt-get update && \
apt-get install -y --no-install-recommends  --no-install-suggests \
    $(cat $DEPENDENCIES_FILE | grep -v '#') \
