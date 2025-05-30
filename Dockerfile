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
WORKDIR /build/chromium
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
        libx11-xcb-dev libxt-dev xvfb yasm nasm rlwrap llvm clang lld

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

# Run fetch and build separately to allow more Docker caching
WORKDIR /firefox
COPY firefox/Makefile Makefile
COPY firefox/cert_bench.diff cert_bench.diff
RUN make mozilla-unified/.fetched
COPY firefox/ .
RUN make inner-build

# Remove some unnecessary binaries
# In particular, libxul is not needed since we have
# statically linked it to xpcshell
RUN rm -rf mozilla-unified/obj-firefox/dist/bin/browser \
           mozilla-unified/obj-firefox/dist/bin/chrome \
           mozilla-unified/obj-firefox/dist/bin/geckodriver \
           mozilla-unified/obj-firefox/dist/bin/hyphenation \
           mozilla-unified/obj-firefox/dist/bin/http3server \
           mozilla-unified/obj-firefox/dist/bin/libmozavcodec.so \
           mozilla-unified/obj-firefox/dist/bin/minidump-analyzer \
           mozilla-unified/obj-firefox/dist/bin/fonts \
           mozilla-unified/obj-firefox/dist/bin/dictionaries \
           mozilla-unified/obj-firefox/dist/bin/libxul.so

# Resolve symlinks in obj-*/dist/bin/modules for later use
RUN cp -rL mozilla-unified/obj-firefox/dist/bin \
           mozilla-unified/obj-firefox/dist/bin-resolved

RUN rm -rf $(find mozilla-unified/obj-firefox/dist/bin-resolved \
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
    /firefox/mozilla-unified/obj-firefox/dist/bin-resolved \
    /firefox/mozilla-unified/obj-firefox/dist/bin

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
RUN rm -rf /armor/src/armor-driver/Morpheus

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
           /ceres/src/extras.tar.gz \
           /ceres/*.pdf

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

COPY verdict verdict-src
RUN rm -rf /verdict-src/deps/verus/source/docs \
           /verdict-src/deps/verus/source/rust_verify/example

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

COPY --from=verdict-build /verdict-src/ /verdict/

######################################################
# ██████╗ ██╗   ██╗███████╗████████╗██╗     ███████╗ #
# ██╔══██╗██║   ██║██╔════╝╚══██╔══╝██║     ██╔════╝ #
# ██████╔╝██║   ██║███████╗   ██║   ██║     ███████╗ #
# ██╔══██╗██║   ██║╚════██║   ██║   ██║     ╚════██║ #
# ██║  ██║╚██████╔╝███████║   ██║   ███████╗███████║ #
# ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚══════╝ #
######################################################

##################################
FROM verdict-build AS rustls-build
##################################
COPY rustls rustls
RUN cd rustls && \
    cargo build --release --features verdict-aws-lc && \
    mv target/release/tlsclient-mio target/release/tlsclient-mio-aws-lc && \
    cargo build --release

##############################
FROM scratch AS rustls-install
##############################
COPY --from=rustls-build \
    /rustls/target/release/tlsclient-mio-aws-lc \
    /rustls/target/release/tlsclient-mio \
    /rustls/target/release/

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
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        build-essential file python3-pip upx-ucl

# Install all builds
COPY --from=chromium-install / .
COPY --from=firefox-install / .
COPY --from=armor-install / .
COPY --from=ceres-install / .
COPY --from=hammurabi-install / .
COPY --from=openssl-install / .
COPY --from=verdict-install / .
COPY --from=rustls-install / .

# Strip all ELF binaries
RUN find . -type f -exec sh -c 'file -b "$1" | grep -q ELF && strip "$1"' _ {} \;

# Bundle scripts/perf_results.py into a separate executable
# to avoid installing pandas, matplotlib, and numpy in the final image
COPY scripts/perf_results.py scripts/perf_results.py
RUN python3 -m pip install \
        --break-system-packages \
        pyinstaller==6.12.0 \
        pandas==2.2.3 \
        matplotlib==3.9.2 \
        seaborn==0.13.2
RUN cd /tmp && \
    PYTHONOPTIMIZE=2 pyinstaller --onefile --strip --clean \
        --exclude-module tkinter \
        --exclude-module unittest \
        --exclude-module pytest \
        --distpath /verdict-bench/scripts \
        --name perf_results \
        /verdict-bench/scripts/perf_results.py

# Run UPX on some large binaries
RUN cat <<EOF > /verdict-bench/compressed.txt
/verdict-bench/firefox/mozilla-unified/obj-firefox/dist/bin/xpcshell
/verdict-bench/ceres/build/extras/CVC4/cvc4
/verdict-bench/ceres/build/extras/stringprep/runStringPrep
/verdict-bench/armor/src/armor-driver/armor-bin
/usr/bin/python3.12
/verdict-bench/verdict/target/release/verdict
/verdict-bench/verdict/target/release/verdict-aws-lc
/verdict-bench/hammurabi/target/release/bench
/verdict-bench/rustls/target/release/tlsclient-mio
/verdict-bench/rustls/target/release/tlsclient-mio-aws-lc
/verdict-bench/openssl/cert_bench
EOF

RUN upx --lzma --best $(cat /verdict-bench/compressed.txt | xargs)

##################################
FROM ubuntu:24.04 AS final-runtime
##################################

WORKDIR /verdict-bench

ENV PYTHONDONTWRITEBYTECODE=1
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install \
        --no-install-recommends -y \
        make libfaketime python3 python3-pip libgtk-3-0 \
        libx11-xcb1 libdbus-glib-1-2 libxt6 swi-prolog-nox \
        iproute2 sudo jq upx-ucl

COPY requirements.txt requirements.txt
RUN python3 -m pip install \
        -r requirements.txt \
        --no-cache-dir --no-compile \
        --break-system-packages \
        --no-cache-dir && \
    rm requirements.txt

# Install busybox to replace coreutils
RUN apt-get install -y busybox && \
    dpkg --purge --force-depends --force-remove-essential coreutils && \
    busybox --install -s /usr/bin

COPY --from=final-strip /verdict-bench/ /verdict-bench/

# Misc
COPY data/ct-log data/ct-log
COPY data/end-to-end data/end-to-end
COPY data/limbo.json data/limbo.json
COPY scripts scripts
COPY Makefile Makefile
COPY README.md README.md

# Remove unnecessary test cases from limbo.json
COPY ref-results/limbo-chrome.csv limbo-chrome.csv
RUN cut -d, -f1 limbo-chrome.csv | jq -R -s -c 'split("\n") | map(select(. != ""))' > used_tests.json && \
    jq --slurpfile used_tests used_tests.json \
        '{ version: .version, testcases: [.testcases[] | select(.id as $id | $used_tests[0] | index($id))] }' data/limbo.json | \
    jq -c . > data/limbo-new.json && \
    rm used_tests.json limbo-chrome.csv data/limbo.json && \
    mv data/limbo-new.json data/limbo.json

# Add a nice welcome message
RUN cat <<EOF2 >> /root/.bashrc

# Check ANSI support
if [[ -t 1 ]] && tput setaf 1 >/dev/null 2>&1 && [[ -z "${NO_COLOR-}" ]]; then
    bold=\$(tput bold)
    italic=\$(tput sitm)
    underline=\$(tput smul)
    reset=\$(tput sgr0)
    green=\$(tput setaf 2)
else
    bold=
    italic=
    underline=
    reset=
    green=
fi

cat <<EOF
Welcome to the artifact accompanying the paper

    \${bold}\${italic}Towards Practical, End-to-End Formally Verified X.509 Certificate Validators with Verdict\${reset}

For additional details, see the artifact appendix.
If the appendix is unavailable, see README.md.

${bold}TL;DR:${reset}

    \\\$ make test\${reset}      \${green}# Sanity check\${reset}
    \\\$ rm -rf results\${reset}
    \\\$ make eval\${reset}      \${green}# Run the full benchmark\${reset}
    \\\$ make figures\${reset}   \${green}# Show results\${reset}

EOF

PS1='\w \\\$ '
EOF2

# Cleanup and remove unnecessary files
RUN apt-get purge -y python3-pip file openssl jq && \
    apt-get purge --allow-remove-essential -y perl-base && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* \
           /var/cache/* \
           /root/.cache \
           /usr/lib/systemd \
           /usr/lib/x86_64-linux-gnu/systemd \
           /usr/share/icons \
           /usr/share/mime \
           /usr/share/doc \
           /usr/share/X11 \
           /usr/share/gtk-3.0 \
           /usr/share/fonts \
           /usr/share/bash-completion && \
    find /usr | grep -E "(__pycache__|\.pyc$)" | xargs rm -rf && \
    find /var/log -type f -delete && \
    rm -rf /usr/lib/x86_64-linux-gnu/libicudata.so* \
           /usr/lib/x86_64-linux-gnu/libicuuc.so* \
           /usr/lib/x86_64-linux-gnu/libicui18n.so* \
           /usr/lib/swi-prolog/library/chr \
           /usr/lib/swi-prolog/library/http \
           /usr/lib/swi-prolog/library/semweb \
           /usr/lib/swi-prolog/library/pldoc \
           /usr/lib/swi-prolog/library/dialect \
           /usr/lib/swi-prolog/library/protobufs \
           /usr/lib/swi-prolog/library/latex2html \
           /usr/lib/swi-prolog/library/pengines.pl \
           /usr/lib/swi-prolog/library/prolog_colour.pl \
           /usr/lib/swi-prolog/include \
           /usr/bin/systemctl \
           /usr/bin/systemd-* \
           /usr/bin/cvtsudoers \
           /usr/bin/localedef

# Some additional unneeded, large shared libraries
# according to the output of
# ```
# export LD_LIBRARY_PATH=firefox/mozilla-unified/obj-firefox/dist/bin; for binary in /bin/* /usr/local/sbin/* /usr/local/bin/* /usr/sbin/* /usr/bin/* firefox/mozilla-unified/obj-firefox/dist/bin/xpcshell; do [ -f "$binary" ] && [ -r "$binary" ] && (file -L "$binary" | grep -q "ELF\|shared object") && ldd "$binary" 2>/dev/null | grep -o '/[^ :),]*' | sed "s|$| $binary|"; done | awk '{lib=$1; bin=$2; if(!(lib in libs)) libs[lib]=bin; else libs[lib]=libs[lib]", "bin} END {for(lib in libs) {cmd="du -L -h \""lib"\" 2>/dev/null | cut -f1"; cmd|getline hsize; close(cmd); if(hsize) {printf "%s\t%s (used by: %s)\n", hsize, lib, libs[lib]} else printf "0B\t%s (used by: %s)\n", lib, libs[lib]}}' | sort -h
# ```
# This might broke some dependencies but should be easy to fix
# dpkg --purge --force-depends ubuntu-mono
# cp -L /usr/lib/x86_64-linux-gnu/libsystemd.so.0 \
#       /usr/lib/x86_64-linux-gnu/libsystemd.so.0.backup && \
# dpkg --remove --force-depends \
#     shared-mime-info \
#     systemd \
#     systemd-dev \
#     libsystemd-shared \
#     systemd-sysv && \
# mv /usr/lib/x86_64-linux-gnu/libsystemd.so.0.backup \
#    /usr/lib/x86_64-linux-gnu/libsystemd.so.0

# Unpack all compressed libraries before entry
RUN cat <<EOF > /entry.sh
#!/bin/sh

FILES=\$(cat /verdict-bench/compressed.txt)
TOTAL=\$(echo "\$FILES" | wc -w)
COUNT=0

for FILE in \$FILES; do
    COUNT=\$((COUNT + 1))
    printf "\r[%d/%d] Loading image" "\$COUNT" "\$TOTAL"
    upx -d "\$FILE" > /dev/null 2>&1
done
printf "\r\033[K"

exec "\$@"
EOF
RUN chmod +x /entry.sh

#####################
FROM scratch AS final
#####################
COPY --from=final-runtime / /
WORKDIR /verdict-bench
ENTRYPOINT [ "/entry.sh" ]
CMD [ "/bin/bash" ]
