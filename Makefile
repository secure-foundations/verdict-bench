VERDICT_AWS_LC = verdict/target/release/verdict-aws-lc
VERDICT_NORMAL = verdict/target/release/verdict
VERDICT = $(VERDICT_NORMAL)

# Targets for performance benchmarking (Eval 1)
BENCH_TARGETS = \
	chrome verdict-chrome-aws-lc verdict-chrome \
	firefox verdict-firefox-aws-lc verdict-firefox \
	openssl verdict-openssl-aws-lc verdict-openssl \
	armor ceres \
	hammurabi-chrome hammurabi-firefox

# Targets for differential testing (Eval 2)
DIFF_TARGETS = \
	chrome verdict-chrome \
	firefox verdict-firefox \
	openssl verdict-openssl

# Common configurations
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

# Additional flags (for verdict frontend)
FLAGS =
OUTPUT = > /dev/stdout

.PHONY: main
main:
	@echo "Please see README for the usage of this Makefile"

# Run all Limbo tests
limbo: $(foreach target,$(DIFF_TARGETS),results/limbo-$(target).csv)

# Run all differential tests (on CT logs)
diff: $(foreach target,$(DIFF_TARGETS),results/diff-$(target).csv)

# Run all performance benchmarks
bench: $(foreach target,$(BENCH_TARGETS),results/bench-$(target).csv)

# x509-limbo test command
results/limbo-%.csv: OUTPUT = > $@
results/limbo-%.csv:
	$(VERDICT) limbo $* $(LIMBO_JSON) \
		--bench-repo . $(FLAGS) \
		$(OUTPUT)

# For differential tests on CT logs, we do not need to
# repeat validation on each chain
results/diff-%.csv: REPEAT = 1
results/diff-%.csv: OUTPUT = -o results/diff-$*.csv
results/diff-%.csv: run-bench-%
	@true

# Reduce benchmark size for some implementations
results/bench-armor.csv: override FLAGS += --sample 0.001
results/bench-ceres.csv: override FLAGS += --sample 0.001
results/bench-hammurabi-chrome.csv: override FLAGS += --sample 0.01
results/bench-hammurabi-firefox.csv: override FLAGS += --sample 0.01

# Default output location of all benchmarks
results/bench-%.csv: OUTPUT = -o results/bench-$*.csv
results/bench-%.csv: run-bench-%
	@true

# Benchmarking command
.PHONY: run-bench-%
run-bench-%: SHELL = /bin/bash
run-bench-%: $(VERDICT)
	@if [ -z "$(CT_LOG)" ]; then \
		echo "CT_LOG is not set"; \
		exit 1; \
	fi
	$(if $(ISOLATE_CORES),taskset -c $(ISOLATE_CORES),)
	$(if $(filter aws-lc,$*),$(VERDICT_AWS_LC),$(VERDICT)) bench-ct-logs \
		$(patsubst %-aws-lc,%,$*) \
		$(ROOTS) $(CT_LOG_INTS) $(CT_LOG_TESTS) \
		-t $(TIMESTAMP) \
		-n $(REPEAT) \
		--bench-repo . \
		$(if $(filter $(NO_DOMAIN),$*),--no-domain,) \
		$(FLAGS) $(OUTPUT)

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
