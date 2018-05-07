#!/usr/bin/env bash

if ! which docker > /dev/null; then
	echo "docker needs to be installed"
	exit 1
fi

: ${IMAGE:?"Need to set IMAGE, e.g. gcr.io/<repo>/<your>-operator"}

echo "building container ${IMAGE}..."
docker build -t "${IMAGE}" -f tmp/build/Dockerfile .
