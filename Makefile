VERDICT_AWS_LC = verdict/target/release/verdict-aws-lc
VERDICT_NORMAL = verdict/target/release/verdict
VERDICT = $(VERDICT_NORMAL)

DEPS = armor ceres chromium firefox hammurabi openssl

CURRENT_DIR = $(shell pwd)

# Configurations for benchmarking
ROOTS = data/ct-log/roots.pem
CT_LOG = data/ct-log
CT_LOG_INTS = $(CT_LOG)/ints
CT_LOG_TESTS = $(CT_LOG)/certs/cert-list-*.txt
TIMESTAMP = 1601603624
REPEAT = 10
NO_DOMAIN = ceres armor # Implementations that do not support hostname validation

LIMBO_JSON = data/limbo.json

# Settings for reducing noise (need to be changed on the test machine)
ISOLATE_CORES = # e.g. 0,2,4,6
CORE_FREQUENCY = # e.g. 2401000

BENCH_FLAGS = # Additional benchmarking flags
BENCH_OUTPUT = > /dev/stdout

.PHONY: main
main:
	@echo "Please see README for the usage of this Makefile"

results:
	mkdir -p results

# x509-limbo test command
.PHONY: limbo-%
limbo-%: override BENCH_OUTPUT = > results/limbo-$*.txt
limbo-%: results
	$(VERDICT) limbo $* $(LIMBO_JSON) \
		--bench-repo . $(BENCH_FLAGS) \
		$(BENCH_OUTPUT)

# Benchmarking command
.PHONY: do-bench-%
do-bench-%: SHELL = /bin/bash
do-bench-%: $(VERDICT)
	@if [ -z "$(CT_LOG)" ]; then \
		echo "CT_LOG is not set"; \
		exit 1; \
	fi
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

# Default output location of all benchmarks
bench-%: override BENCH_OUTPUT = -o results/bench-$*.txt

.PHONY: bench-chrome
bench-chrome: results do-bench-chrome

.PHONY: bench-firefox
bench-firefox: results do-bench-firefox

.PHONY: bench-openssl
bench-openssl: results do-bench-openssl

.PHONY: bench-armor
bench-armor: override BENCH_FLAGS += --sample 0.001
bench-armor: results do-bench-armor

.PHONY: bench-ceres
bench-ceres: override BENCH_FLAGS += --sample 0.001
bench-ceres: results do-bench-ceres

.PHONY: bench-hammurabi-chrome
bench-hammurabi-chrome: override BENCH_FLAGS += --sample 0.01
bench-hammurabi-chrome: results do-bench-hammurabi-chrome

.PHONY: bench-hammurabi-firefox
bench-hammurabi-firefox: override BENCH_FLAGS += --sample 0.01
bench-hammurabi-firefox: results do-bench-hammurabi-firefox

.PHONY: bench-verdict-chrome
bench-verdict-chrome: results do-bench-verdict-chrome

.PHONY: bench-verdict-firefox
bench-verdict-firefox: results do-bench-verdict-firefox

.PHONY: bench-verdict-openssl
bench-verdict-openssl: results do-bench-verdict-openssl

.PHONY: bench-verdict-chrome-aws-lc
bench-verdict-chrome-aws-lc: override VERDICT = $(VERDICT_AWS_LC)
bench-verdict-chrome-aws-lc: results do-bench-verdict-chrome

.PHONY: bench-verdict-firefox-aws-lc
bench-verdict-firefox-aws-lc: override VERDICT = $(VERDICT_AWS_LC)
bench-verdict-firefox-aws-lc: results do-bench-verdict-firefox

.PHONY: bench-verdict-openssl-aws-lc
bench-verdict-openssl-aws-lc: override VERDICT = $(VERDICT_AWS_LC)
bench-verdict-openssl-aws-lc: results do-bench-verdict-openssl

# Build two versions of Verdict: one with the normal, verified crypto primitives
# the other $(VERDICT_AWS_LC) with more performance but unverified primitives
$(VERDICT_NORMAL) $(VERDICT_AWS_LC) &:
	cd verdict && \
	source tools/activate.sh && \
	vargo build --release --features aws-lc
	mv $(VERDICT_NORMAL) $(VERDICT_AWS_LC)

	cd verdict && \
	source tools/activate.sh && \
	vargo build --release
