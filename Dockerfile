ARG DEPOT_TOOLS_REPO=https://chromium.googlesource.com/chromium/tools/depot_tools.git
ARG DEPOT_TOOLS_COMMIT=c08c71bedfbb76a839518633ce2ea92feaf36163

# Using an old version of Ubuntu for building Chrome
FROM ubuntu:20.04

RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        build-essential python python3 curl clang \
        git pkg-config libncurses5 libnss3

WORKDIR /build

# Install Google's depot_tools
ARG DEPOT_TOOLS_REPO
ARG DEPOT_TOOLS_COMMIT
RUN mkdir depot_tools && cd depot_tools && \
    git init && \
    git remote add origin ${DEPOT_TOOLS_REPO} && \
    git fetch --depth 1 origin ${DEPOT_TOOLS_COMMIT} && \
    git checkout FETCH_HEAD

ENV DEPOT_TOOLS_UPDATE=0
ENV PATH="/build/depot_tools:${PATH}"

WORKDIR /build/local
