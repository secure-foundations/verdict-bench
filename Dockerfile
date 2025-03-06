# This Dockerfile is used for building a standalone image
# including all compiled binaries and runtime dependencies
# of Verdict and other X.509 tools being benchmarked
#
# For each <tool> being compiled, `<tool>-build` stage is
# the build environment, and `<tool>-install` is a baseless
# image containing on the compiled binary stored at `/<tool>`

#######################################################################
#  ██████╗██╗  ██╗██████╗  ██████╗ ███╗   ███╗██╗██╗   ██╗███╗   ███╗ #
# ██╔════╝██║  ██║██╔══██╗██╔═══██╗████╗ ████║██║██║   ██║████╗ ████║ #
# ██║     ███████║██████╔╝██║   ██║██╔████╔██║██║██║   ██║██╔████╔██║ #
# ██║     ██╔══██║██╔══██╗██║   ██║██║╚██╔╝██║██║██║   ██║██║╚██╔╝██║ #
# ╚██████╗██║  ██║██║  ██║╚██████╔╝██║ ╚═╝ ██║██║╚██████╔╝██║ ╚═╝ ██║ #
#  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚═╝ ╚═════╝ ╚═╝     ╚═╝ #
#######################################################################
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

COPY chromium chromium
WORKDIR chromium
RUN make src/out/Release/cert_bench

FROM scratch AS chromium-install
COPY --from=chromium-build /build/chromium/src/out/Release/cert_bench \
                           /chromium/src/out/Release/cert_bench

########################################################
# ███████╗██╗██████╗ ███████╗███████╗ ██████╗ ██╗  ██╗ #
# ██╔════╝██║██╔══██╗██╔════╝██╔════╝██╔═══██╗╚██╗██╔╝ #
# █████╗  ██║██████╔╝█████╗  █████╗  ██║   ██║ ╚███╔╝  #
# ██╔══╝  ██║██╔══██╗██╔══╝  ██╔══╝  ██║   ██║ ██╔██╗  #
# ██║     ██║██║  ██║███████╗██║     ╚██████╔╝██╔╝ ██╗ #
# ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ #
########################################################

##################################
FROM ubuntu:20.04 AS firefox-build
##################################

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
COPY firefox firefox
WORKDIR firefox
RUN make inner-build

# Remove some unnecessary binaries
RUN rm -rf mozilla-unified/obj-x86_64-pc-linux-gnu/dist/bin/browser \
           mozilla-unified/obj-x86_64-pc-linux-gnu/dist/bin/chrome \
           mozilla-unified/obj-x86_64-pc-linux-gnu/dist/bin/geckodriver \
           mozilla-unified/obj-x86_64-pc-linux-gnu/dist/bin/hyphenation \
           mozilla-unified/obj-x86_64-pc-linux-gnu/dist/bin/http3server \
           mozilla-unified/obj-x86_64-pc-linux-gnu/dist/bin/libmozavcodec.so \
           mozilla-unified/obj-x86_64-pc-linux-gnu/dist/bin/minidump-analyzer \
           mozilla-unified/obj-x86_64-pc-linux-gnu/dist/bin/font

# Resolve symlinks in obj-*/dist/bin/modules for later use
RUN cp -rL mozilla-unified/obj-x86_64-pc-linux-gnu/dist/bin \
           mozilla-unified/obj-x86_64-pc-linux-gnu/dist/bin-resolved

RUN rm -rf $(find mozilla-unified/obj-x86_64-pc-linux-gnu/dist/bin-resolved \
                -type f -executable \
                ! -name "*.so*" \
                ! -name "xpcshell" \
                ! -name "run-mozilla.sh" -print)

###############################
FROM scratch AS firefox-install
###############################

COPY --from=firefox-build \
    /firefox/cert_bench.js \
    /firefox/cert_bench.sh \
    /firefox/

COPY --from=firefox-build \
    /firefox/mozilla-unified/obj-x86_64-pc-linux-gnu/dist/bin-resolved \
    /firefox/mozilla-unified/obj-x86_64-pc-linux-gnu/dist/bin

######################################################
#  ██████╗ ████████╗██╗  ██╗███████╗██████╗ ███████╗ #
# ██╔═══██╗╚══██╔══╝██║  ██║██╔════╝██╔══██╗██╔════╝ #
# ██║   ██║   ██║   ███████║█████╗  ██████╔╝███████╗ #
# ██║   ██║   ██║   ██╔══██║██╔══╝  ██╔══██╗╚════██║ #
# ╚██████╔╝   ██║   ██║  ██║███████╗██║  ██║███████║ #
#  ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝ #
######################################################

################################
FROM ubuntu:24.04 AS other-build
################################

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

################################################
#  █████╗ ██████╗ ███╗   ███╗ ██████╗ ██████╗  #
# ██╔══██╗██╔══██╗████╗ ████║██╔═══██╗██╔══██╗ #
# ███████║██████╔╝██╔████╔██║██║   ██║██████╔╝ #
# ██╔══██║██╔══██╗██║╚██╔╝██║██║   ██║██╔══██╗ #
# ██║  ██║██║  ██║██║ ╚═╝ ██║╚██████╔╝██║  ██║ #
# ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝ #
################################################

###############################
FROM other-build AS armor-build
###############################
COPY armor armor
RUN cd armor && make

#############################
FROM scratch AS armor-install
#############################
COPY --from=armor-build /armor/src/armor-driver \
                        /armor/src/armor-driver

############################################
#  ██████╗███████╗██████╗ ███████╗███████╗ #
# ██╔════╝██╔════╝██╔══██╗██╔════╝██╔════╝ #
# ██║     █████╗  ██████╔╝█████╗  ███████╗ #
# ██║     ██╔══╝  ██╔══██╗██╔══╝  ╚════██║ #
# ╚██████╗███████╗██║  ██║███████╗███████║ #
#  ╚═════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝ #
############################################

###############################
FROM other-build AS ceres-build
###############################
COPY ceres ceres
RUN cd ceres && make
RUN rm -rf /ceres/test \
           /ceres/src/extras \
           /ceres/src/extras.tar.gz

#############################
FROM scratch AS ceres-install
#############################
COPY --from=ceres-build /ceres /ceres

##############################################################################
# ██╗  ██╗ █████╗ ███╗   ███╗███╗   ███╗██╗   ██╗██████╗  █████╗ ██████╗ ██╗ #
# ██║  ██║██╔══██╗████╗ ████║████╗ ████║██║   ██║██╔══██╗██╔══██╗██╔══██╗██║ #
# ███████║███████║██╔████╔██║██╔████╔██║██║   ██║██████╔╝███████║██████╔╝██║ #
# ██╔══██║██╔══██║██║╚██╔╝██║██║╚██╔╝██║██║   ██║██╔══██╗██╔══██║██╔══██╗██║ #
# ██║  ██║██║  ██║██║ ╚═╝ ██║██║ ╚═╝ ██║╚██████╔╝██║  ██║██║  ██║██████╔╝██║ #
# ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝ #
##############################################################################

###################################
FROM other-build AS hammurabi-build
###################################
COPY hammurabi hammurabi
RUN cd hammurabi && make

#################################
FROM scratch AS hammurabi-install
#################################

COPY --from=hammurabi-build \
    /hammurabi/target/release/bench \
    /hammurabi/target/release/bench

COPY --from=hammurabi-build \
    /hammurabi/prolog/bin \
    /hammurabi/prolog/bin

###############################################################
#  ██████╗ ██████╗ ███████╗███╗   ██╗███████╗███████╗██╗      #
# ██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██╔════╝██║      #
# ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗███████╗██║      #
# ██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║╚════██║╚════██║██║      #
# ╚██████╔╝██║     ███████╗██║ ╚████║███████║███████║███████╗ #
#  ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝╚══════╝╚══════╝╚══════╝ #
###############################################################

#################################
FROM other-build AS openssl-build
#################################
COPY openssl openssl
RUN cd openssl && make

###############################
FROM scratch AS openssl-install
###############################
COPY --from=openssl-build /openssl/cert_bench /openssl/cert_bench

#########################################################
# ██╗   ██╗███████╗██████╗ ██████╗ ██╗ ██████╗████████╗ #
# ██║   ██║██╔════╝██╔══██╗██╔══██╗██║██╔════╝╚══██╔══╝ #
# ██║   ██║█████╗  ██████╔╝██║  ██║██║██║        ██║    #
# ╚██╗ ██╔╝██╔══╝  ██╔══██╗██║  ██║██║██║        ██║    #
#  ╚████╔╝ ███████╗██║  ██║██████╔╝██║╚██████╗   ██║    #
#   ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═════╝ ╚═╝ ╚═════╝   ╚═╝    #
#########################################################

#################################
FROM other-build AS verdict-build
#################################
COPY verdict verdict
SHELL [ "/bin/bash", "-c" ]
RUN cd verdict && \
    source tools/activate.sh && \
    vargo build --release --features aws-lc && \
    mv target/release/verdict target/release/verdict-aws-lc && \
    vargo build --release

###############################
FROM scratch AS verdict-install
###############################
COPY --from=verdict-build \
    /verdict/target/release/verdict-aws-lc \
    /verdict/target/release/verdict \
    /verdict/target/release/

#########################################
# ███████╗██╗███╗   ██╗ █████╗ ██╗      #
# ██╔════╝██║████╗  ██║██╔══██╗██║      #
# █████╗  ██║██╔██╗ ██║███████║██║      #
# ██╔══╝  ██║██║╚██╗██║██╔══██║██║      #
# ██║     ██║██║ ╚████║██║  ██║███████╗ #
# ╚═╝     ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝ #
#########################################

################################
FROM ubuntu:24.04 AS final-strip
################################

# Copy compiled binaries from previous stages
WORKDIR /verdict-bench

RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential file

# Install all builds
COPY --from=chromium-install / .
COPY --from=firefox-install / .
COPY --from=armor-install / .
COPY --from=ceres-install / .
COPY --from=hammurabi-install / .
COPY --from=openssl-install / .
COPY --from=verdict-install / .

# Strip all ELF binaries
RUN find . -type f -exec sh -c 'file -b "$1" | grep -q ELF && strip "$1"' _ {} \;

##################################
FROM ubuntu:24.04 AS final-runtime
##################################

COPY --from=final-strip /verdict-bench /verdict-bench
WORKDIR /verdict-bench

COPY requirements.txt requirements.txt
RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        make libfaketime python3-pip libgtk-3-0 \
        libx11-xcb1 libdbus-glib-1-2 libxt6 swi-prolog-nox && \
    python3 -m pip install -r requirements.txt \
        --break-system-packages \
        --no-cache-dir && \
    DEBIAN_FRONTEND=noninteractive apt-get purge -y python3-pip file && \
    DEBIAN_FRONTEND=noninteractive apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Misc
COPY data data
COPY Makefile Makefile

#####################
FROM scratch AS final
#####################
COPY --from=final-runtime / /
WORKDIR /verdict-bench
ENTRYPOINT [ "/bin/bash" ]
