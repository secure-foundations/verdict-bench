# Some compilation environments requires docker
# (e.g., old versions of Chrome and Firefox)
FROM cruizba/ubuntu-dind:noble-latest

# Some dependencies for compiling OpenSSL, Hammurabi, ARMOR, and CERES
RUN apt-get update && \
    apt-get install -y \
        build-essential git locales swi-prolog sudo \
        zlib1g-dev libncurses5-dev opam \
        python3 python3-pip ghc libghc-regex-compat-dev libghc-text-icu-dev && \
    locale-gen en_US.UTF-8 && \
    rm -rf /var/lib/apt/lists/*

ENV LANG=en_US.UTF-8
ENV LANGUAGE=en_US:en
ENV LC_ALL=en_US.UTF-8

# Stack for compiling ARMOR
RUN curl -sSL https://get.haskellstack.org/ | sh && \
    stack setup 8.8.4

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y

RUN git config --global safe.directory '*'

ENV PATH="$PATH:/root/.cargo/bin"
