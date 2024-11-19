#!/bin/bash

CHROMIUM_REPO=https://chromium.googlesource.com/chromium/src.git
CHROMIUM_COMMIT=0590dcf7b036e15c133de35213be8fe0986896aa

set -euo pipefail

build_target=$1
build_type=${2:-debug}

mkdir -p src
cd src

if [[ -d .git ]] && [[ "$(git rev-parse HEAD)" == "$CHROMIUM_COMMIT" ]]; then
    echo "### chromium@$CHROMIUM_COMMIT already fetched"
else
    git init
    git remote add origin $CHROMIUM_REPO
    git fetch --depth 1 origin $CHROMIUM_COMMIT
    git checkout FETCH_HEAD
    gclient sync --no-history
    echo "### fetched chromium@$CHROMIUM_COMMIT"
fi

# [[ -z "$HOST_UID" ]] || [[ -z "$HOST_GID" ]] || chown -R $HOST_UID:$HOST_GID .

if [[ "$build_type" == "debug" ]]; then
    [[ -d out/Debug ]] || gn gen out/Debug
    autoninja -C out/Debug $build_target
    chmod -R 777 out/Debug
elif [[ "$build_type" == "release" ]]; then
    [[ -d out/Release ]] || gn gen out/Release --args="is_debug=false"
    autoninja -C out/Release $build_target
    chmod -R 777 out/Debug
else
    echo "unknown build type $build_type"
    exit 1
fi
