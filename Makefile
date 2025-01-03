DOCKER = sudo docker
DOCKER_IMAGE_TAG = verdict-bench-build
DOCKER_FLAGS = --privileged

VERUS = verus/source/target-verus/release/verus
VERUSC = verdict/tools/verusc/target/release/verusc

VERDICT_AWS_LC = verdict/target/release/frontend-aws-lc
VERDICT_NORMAL = verdict/target/release/frontend
VERDICT = $(VERDICT_NORMAL)

DEPS = armor ceres openssl hammurabi chromium firefox

CURRENT_DIR = $(shell pwd)

# Configurations for benchmarking
ROOTS = verdict/chain/tests/roots.pem
CT_LOG_INTS = $(CT_LOG)/ints
CT_LOG_TESTS = $(CT_LOG)/certs/cert-list-*.txt
TIMESTAMP = 1601603624
REPEAT = 10
NO_DOMAIN = ceres armor # Implementations that do not support hostname validation

# Settings for reducing noise (need to be changed on the test machine)
ISOLATE_CORES = # e.g. 0,2,4,6
CORE_FREQUENCY = # e.g. 2401000

# To be configured
CT_LOG = # Main CT log directory
BENCH_FLAGS = # Additional benchmarking flags
BENCH_OUTPUT = > /dev/stdout

.PHONY: main
main:
	@echo "Please see README for the usage of this Makefile"

# Main benchmarking command
.PHONY: do-bench-%
do-bench-%: SHELL = /bin/bash
do-bench-%: $(VERDICT)
	@if [ -z "$(CT_LOG)" ]; then \
		echo "CT_LOG is not set"; \
		exit 1; \
	fi
# ceres requires some Python dependencies
	$(if $(filter ceres,$*),python3 -m venv .venv && \
	source .venv/bin/activate && \
	pip3 install -r requirements.txt &&,) \
	$(if $(ISOLATE_CORES),taskset -c $(ISOLATE_CORES),) $(VERDICT) bench-ct-logs $* \
		$(ROOTS) $(CT_LOG_INTS) $(CT_LOG_TESTS) \
		-t $(TIMESTAMP) \
		-n $(REPEAT) \
		--bench-repo . \
		$(if $(filter $(NO_DOMAIN),$*),--no-domain,) \
		$(BENCH_FLAGS) $(BENCH_OUTPUT)

# Some configurations to reduce noise
.PHONY: reduce-noise
reduce-noise:
# Disable hyperthreading
	echo off | sudo tee /sys/devices/system/cpu/smt/control
	@if [ -n "$(ISOLATE_CORES)" ]; then \
		echo "current isolated cores: $$(cat /sys/devices/system/cpu/isolated)"; \
	fi
	@if [ -n "$(ISOLATE_CORES)" ] && [ -n "$(CORE_FREQUENCY)" ]; then \
		sudo modprobe cpufreq_userspace; \
		sudo cpupower -c $(ISOLATE_CORES) frequency-set --governor userspace; \
		sudo cpupower -c $(ISOLATE_CORES) frequency-set --freq $(CORE_FREQUENCY); \
	fi

# Restore some settings changed in reduce-noise
.PHONY: restore-sys
restore-sys:
	echo on | sudo tee /sys/devices/system/cpu/smt/control
	@if [ -n "$(ISOLATE_CORES)" ]; then \
		sudo cpupower -c $(ISOLATE_CORES) frequency-set --governor powersave; \
	fi

.PHONY: bench-chrome
bench-chrome: do-bench-chrome

.PHONY: bench-firefox
bench-firefox: do-bench-firefox

.PHONY: bench-openssl
bench-openssl: do-bench-openssl

.PHONY: bench-armor
bench-armor: override BENCH_FLAGS += --sample 0.001
bench-armor: do-bench-armor

.PHONY: bench-ceres
bench-ceres: override BENCH_FLAGS += --sample 0.001
bench-ceres: do-bench-ceres

.PHONY: bench-hammurabi-chrome
bench-hammurabi-chrome: override BENCH_FLAGS += --sample 0.01
bench-hammurabi-chrome: do-bench-hammurabi-chrome

.PHONY: bench-hammurabi-firefox
bench-hammurabi-firefox: override BENCH_FLAGS += --sample 0.01
bench-hammurabi-firefox: do-bench-hammurabi-firefox

.PHONY: bench-verdict-chrome
bench-verdict-chrome: do-bench-verdict-chrome

.PHONY: bench-verdict-firefox
bench-verdict-firefox: do-bench-verdict-firefox

.PHONY: bench-verdict-openssl
bench-verdict-openssl: do-bench-verdict-openssl

.PHONY: bench-verdict-chrome-aws-lc
bench-verdict-chrome-aws-lc: override VERDICT = $(VERDICT_AWS_LC)
bench-verdict-chrome-aws-lc: do-bench-verdict-chrome

.PHONY: bench-verdict-firefox-aws-lc
bench-verdict-firefox-aws-lc: override VERDICT = $(VERDICT_AWS_LC)
bench-verdict-firefox-aws-lc: do-bench-verdict-firefox

.PHONY: bench-verdict-openssl-aws-lc
bench-verdict-openssl-aws-lc: override VERDICT = $(VERDICT_AWS_LC)
bench-verdict-openssl-aws-lc: do-bench-verdict-openssl

# Build two versions of Verdict: one with the normal, verified crypto primitives
# the other $(VERDICT_AWS_LC) with more performance but unverified primitives
$(VERDICT_NORMAL) $(VERDICT_AWS_LC) &: $(VERUS) $(VERUSC)
	cd verdict && \
	PATH="$(dir $(realpath $(VERUS))):$$PATH" \
	RUSTC_WRAPPER="$(realpath $(VERUSC))" cargo build --release --features aws-lc
	mv $(VERDICT_NORMAL) $(VERDICT_AWS_LC)
	cd verdict && \
	PATH="$(dir $(realpath $(VERUS))):$$PATH" \
	RUSTC_WRAPPER="$(realpath $(VERUSC))" cargo build --release

$(VERUSC):
	cd verdict/tools/verusc && cargo build --release

# Verus build currently only supports Bash
$(VERUS): SHELL = /bin/bash
$(VERUS):
	cd verus/source && \
	./tools/get-z3.sh && \
	source ../tools/activate && \
	vargo build --release

# Build all other X.509 implementations in the docker environment
.PHONY: deps
deps: build-env submodules
	$(DOCKER) run -it --init \
		$(DOCKER_FLAGS) \
		-v $(CURRENT_DIR):$(CURRENT_DIR) \
		-w $(CURRENT_DIR) \
		$(DOCKER_IMAGE_TAG) \
		make inner-deps HOST_USER=$(shell id -u)

.PHONY: dep-%
dep-%: build-env submodules
	$(DOCKER) run -it --init \
		$(DOCKER_FLAGS) \
		-v $(CURRENT_DIR):$(CURRENT_DIR) \
		-w $(CURRENT_DIR) \
		$(DOCKER_IMAGE_TAG) \
		make inner-dep-$* HOST_USER=$(shell id -u)

.PHONY: submodules
submodules:
	git submodule update --init --recursive

.PHONY: build-env
build-env:
	$(DOCKER) build . -t $(DOCKER_IMAGE_TAG)

.PHONY: enter
enter: build-env
	$(DOCKER) run -it --init \
		$(DOCKER_FLAGS) \
		-v $(CURRENT_DIR):$(CURRENT_DIR) \
		-w $(CURRENT_DIR) \
		$(DOCKER_IMAGE_TAG)

##### Targets below are executed within Docker #####

.PHONY: inner-deps
inner-deps: $(foreach dep,$(DEPS),inner-dep-$(dep))

.PHONY: inner-dep-%
inner-dep-%:
	chown -R $$(whoami) $*
	cd $* && make
	chown -R $(HOST_USER) $*
