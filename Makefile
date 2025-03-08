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

LIBFAKETIME = /usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1
END_TO_END_TIME = 2025-01-16 12:00:00
END_TO_END_DELAY = 5ms
END_TO_END_WARMUP = 20
END_TO_END_REPEAT = 100

# Settings for reducing noise (need to be changed on the test machine)
ISOLATE_CORES = # e.g. 0,2,4,6
CORE_FREQUENCY = # e.g. 2401000

# Additional flags (for verdict frontend)
FLAGS =
OUTPUT = > /dev/stdout

.PHONY: main
main:
	@echo "Please see README for the usage of this Makefile"

results:
	mkdir -p results

# Main evaluation setup
.PHONY: eval-1
eval-1: bench
	python3 scripts/perf_results.py -o results/performance.pdf

.PHONY: eval-2
eval-2: limbo diff
	python3 scripts/diff_results.py

.PHONY: eval-3
eval-3: results results/end-to-end-aws-lc.csv results/end-to-end-libcrux.csv
	python3 scripts/rustls_results.py \
		results/end-to-end-aws-lc.csv \
		results/end-to-end-libcrux.csv

# Parallel commands of tc might conflict
.NOTPARALLEL: results/end-to-end-%.csv
results/end-to-end-%.csv:
	LD_PRELOAD=$(LIBFAKETIME) FAKETIME="@$(END_TO_END_TIME)" \
	python3 scripts/rustls_end_to_end.py data/end-to-end \
		$(if $(filter aws-lc,$*),rustls/target/release/tlsclient-mio-aws-lc,rustls/target/release/tlsclient-mio) \
		--delay $(END_TO_END_DELAY) \
		--warmup $(END_TO_END_WARMUP) \
		--repeat $(END_TO_END_REPEAT) \
		-o results/end-to-end-$*.tmp.csv
	mv results/end-to-end-$*.tmp.csv results/end-to-end-$*.csv

# Run all Limbo tests
.PHONY: limbo
limbo: results $(foreach target,$(DIFF_TARGETS),results/limbo-$(target).csv)

# Run all differential tests (on CT logs)
.PHONY: diff
diff: results $(foreach target,$(DIFF_TARGETS),results/diff-$(target).csv)

# Run all performance benchmarks
.PHONY: bench
bench: results $(foreach target,$(BENCH_TARGETS),results/bench-$(target).csv)

# x509-limbo test command
results/limbo-%.csv:
	$(VERDICT) limbo $* $(LIMBO_JSON) \
		--bench-repo . $(FLAGS) > results/limbo-$*.tmp.csv
	mv results/limbo-$*.tmp.csv results/limbo-$*.csv

# For differential tests on CT logs, we do not need to
# repeat validation on each chain
results/diff-%.csv: REPEAT = 1
results/diff-%.csv: OUTPUT = -o results/diff-$*.tmp.csv
results/diff-%.csv: run-bench-%
	mv results/diff-$*.tmp.csv results/diff-$*.csv

# Reduce benchmark size for some implementations
results/bench-armor.csv: override FLAGS += --sample 0.001
results/bench-ceres.csv: override FLAGS += --sample 0.001
results/bench-hammurabi-chrome.csv: override FLAGS += --sample 0.01
results/bench-hammurabi-firefox.csv: override FLAGS += --sample 0.01

# Default output location of all benchmarks
results/bench-%.csv: OUTPUT = -o results/bench-$*.tmp.csv
results/bench-%.csv: run-bench-%
	mv results/bench-$*.tmp.csv results/bench-$*.csv

# Benchmarking command
.PHONY: run-bench-%
run-bench-%: SHELL = /bin/bash
run-bench-%: $(VERDICT)
	@if [ -z "$(CT_LOG)" ]; then \
		echo "CT_LOG is not set"; \
		exit 1; \
	fi
	$(if $(ISOLATE_CORES),taskset -c $(ISOLATE_CORES),)
	$(if $(filter %-aws-lc,$*),$(VERDICT_AWS_LC),$(VERDICT)) bench-ct-logs \
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
