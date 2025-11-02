#!/bin/bash

BUILD_TIME=$(date -u +'%Y-%m-%dT%H:%M:%SZ')

GIT_VERSION=$(git describe --tags --abbrev=7 --dirty 2>/dev/null || echo "unknown")

# if arch is amd64 set GOAMD64=v2
if [ "$(uname -m)" == "x86_64" ]; then
  export GOAMD64=v2
fi

cd cmd/netgate

go build -a -ldflags="-w -s \
  -X 'main.buildstamp=$BUILD_TIME' \
  -X 'main.gitver=$GIT_VERSION'" \
  "$@"
