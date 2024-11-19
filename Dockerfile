# Using an old version of Ubuntu for building Firefox
FROM ubuntu:20.04

RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        build-essential python python3 curl clang \
        git pkg-config libncurses5 libnss3 mercurial \
        autoconf2.13 unzip uuid zip libasound2-dev \
        libcurl4-openssl-dev libdbus-1-dev libdbus-glib-1-dev \
        libdrm-dev libgtk-3-dev libgtk2.0-dev libpulse-dev \
        libx11-xcb-dev libxt-dev xvfb yasm nasm

# Install NodeJS 11
RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.0/install.sh | bash && \
    . /root/.bashrc && \
    nvm install 11

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- --default-toolchain 1.82.0 -y

# A newer version of Rust is required to compile cbingen@0.14.3
# And then we switch to an older version
RUN . $HOME/.cargo/env && \
    cargo install cbindgen --version 0.14.3 && \
    rustup install 1.43.0 && \
    rustup default 1.43.0

WORKDIR /build/local

RUN ["/bin/bash"]
