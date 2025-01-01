#!/bin/bash
set -e

git submodule update --init --remote
cd src/ && make all && cd ..
