# This Dockerfile extends the base `Dockerfile`
# to actually build all dependencies and bundle
# them into a single Docker image for better
# reproducibility

############################################################################
# Environment for building Chrome (mostly copied from chromium/Dockerfile) #
############################################################################
ARG DEPOT_TOOLS_REPO=https://chromium.googlesource.com/chromium/tools/depot_tools.git
ARG DEPOT_TOOLS_COMMIT=c08c71bedfbb76a839518633ce2ea92feaf36163
FROM ubuntu:20.04 AS chromium-build

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
COPY chromium .
RUN make src/out/Release/cert_bench

############################################################################
# Environment for building Firefox (mostly copied from firefox/Dockerfile) #
############################################################################
FROM ubuntu:20.04 AS firefox-build

RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        build-essential python python3 curl clang \
        git pkg-config libncurses5 libnss3 mercurial \
        autoconf2.13 unzip uuid zip libasound2-dev \
        libcurl4-openssl-dev libdbus-1-dev libdbus-glib-1-dev \
        libdrm-dev libgtk-3-dev libgtk2.0-dev libpulse-dev \
        libx11-xcb-dev libxt-dev xvfb yasm nasm rlwrap

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

# The path must match the final path in the image to avoid a build issue
WORKDIR /verdict-bench/firefox
COPY firefox .
RUN make inner-build

# Resolve symlinks in obj-*/dist/bin/modules for later use
RUN cp -rL mozilla-unified/obj-x86_64-pc-linux-gnu/dist/bin \
           mozilla-unified/obj-x86_64-pc-linux-gnu/dist/bin-resolved

##########################################################################
# Environment for building other tools: ARMOR, CERES, Hammurabi, OpenSSL #
##########################################################################
FROM ubuntu:24.04 AS other-build

# Some dependencies for compiling OpenSSL, Hammurabi, ARMOR, and CERES
RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        build-essential git locales swi-prolog sudo \
        zlib1g-dev libncurses5-dev opam \
        python3 python3-pip ghc libghc-regex-compat-dev libghc-text-icu-dev && \
    locale-gen en_US.UTF-8

ENV LANG=en_US.UTF-8
ENV LANGUAGE=en_US:en
ENV LC_ALL=en_US.UTF-8

# Stack for compiling ARMOR
RUN curl -sSL https://get.haskellstack.org/ | sh && \
    stack setup 8.8.4

# Install Rust
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="$PATH:/root/.cargo/bin"

WORKDIR /verdict-bench

# Build ARMOR and CERES
FROM other-build AS armor-build
COPY armor armor
RUN cd armor && make

FROM other-build AS ceres-build
COPY ceres ceres
RUN cd ceres && make

# Build Hammurabi
FROM other-build AS hammurabi-build
COPY hammurabi hammurabi
RUN cd hammurabi && make

# Build OpenSSL
FROM other-build AS openssl-build
COPY openssl openssl
RUN cd openssl && make

# Build Verdict
FROM other-build AS verdict-build
COPY verdict verdict
SHELL [ "/bin/bash", "-c" ]
RUN cd verdict && \
    source tools/activate.sh && \
    vargo build --release --features aws-lc && \
    mv target/release/verdict target/release/verdict-aws-lc && \
    vargo build --release

#############################
# Preparing the final image #
#############################
FROM ubuntu:24.04 AS final-tmp

# Some runtime dependencies
COPY requirements.txt requirements.txt
RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        make libfaketime python3-pip libgtk-3-0 file \
        libx11-xcb1 libdbus-glib-1-2 libxt6 swi-prolog && \
    rm -rf /var/lib/apt/lists/* && \
    python3 -m pip install -r requirements.txt \
        --break-system-packages \
        --no-cache-dir && \
    DEBIAN_FRONTEND=noninteractive apt-get purge -y python3-pip && \
    DEBIAN_FRONTEND=noninteractive apt-get autoremove -y

# Copy compiled binaries from previous stages
WORKDIR /verdict-bench

# Install Chromium
COPY --from=chromium-build /build/local/src/out/Release/cert_bench chromium/src/out/Release/cert_bench

# Install Firefox (xpcshell) and dependent libraries
# TODO: these dependencies might change in a different Firefox version
COPY --from=firefox-build \
    /verdict-bench/firefox/cert_bench.js \
    /verdict-bench/firefox/cert_bench.sh \
    /verdict-bench/firefox/

COPY --from=firefox-build \
    /verdict-bench/firefox/mozilla-unified/obj-x86_64-pc-linux-gnu/dist/bin-resolved \
    /verdict-bench/firefox/mozilla-unified/obj-x86_64-pc-linux-gnu/dist/bin

# Install ARMOR
COPY --from=armor-build /verdict-bench/armor/src/armor-driver /verdict-bench/armor/src/armor-driver

# Install CERES
COPY --from=ceres-build /verdict-bench/ceres /verdict-bench/ceres

# Install Hammurabi
COPY --from=hammurabi-build \
    /verdict-bench/hammurabi/target/release/bench \
    /verdict-bench/hammurabi/target/release/bench
COPY --from=hammurabi-build \
    /verdict-bench/hammurabi/prolog/bin \
    /verdict-bench/hammurabi/prolog/bin

# Install OpenSSL
COPY --from=openssl-build /verdict-bench/openssl/cert_bench /verdict-bench/openssl/cert_bench

# Install Verdict
COPY --from=verdict-build \
    /verdict-bench/verdict/target/release/verdict-aws-lc \
    /verdict-bench/verdict/target/release/verdict \
    /verdict-bench/verdict/target/release/

# Strip all ELF binaries
RUN find . -type f -exec sh -c 'file -b "$1" | grep -q ELF && strip "$1"' _ {} \;

# Misc
COPY data data
COPY Makefile Makefile

###############
# Final image #
###############
FROM scratch AS final
COPY --from=final-tmp / /
WORKDIR /verdict-bench
ENTRYPOINT [ "/bin/bash" ]
