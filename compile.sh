#!/bin/bash
set -e

git submodule update --init --remote
cd agda-stdlib
git fetch origin v1.7.1
git checkout v1.7.1
cd ..
cd src/ && make all && cd ..
