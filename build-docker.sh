#!/bin/bash

docker buildx build --platform linux/amd64,linux/arm64 -t $1 -f Dockerfile . --push