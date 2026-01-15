#!/bin/bash

set -e

tag="$(date -u +%Y%m%d)-$(openssl rand -hex 4)"

echo "tag: $tag"
docker manifest create docker.io/losfair/zeroserve:$tag
docker build --platform linux/amd64,linux/arm64 --manifest docker.io/losfair/zeroserve:$tag .
docker manifest push docker.io/losfair/zeroserve:$tag
