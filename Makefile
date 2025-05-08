VERDICT_AWS_LC = verdict/target/release/verdict-aws-lc
VERDICT_NORMAL = verdict/target/release/verdict
VERDICT = $(VERDICT_NORMAL)

# Common configurations
ROOTS = data/ct-log/roots.pem
CT_LOG = data/ct-log
CT_LOG_INTS = $(CT_LOG)/ints
CT_LOG_TESTS = $(CT_LOG)/certs/cert-list-*.txt
CT_LOG_TIMESTAMP = 1601603624
NO_DOMAIN = ceres armor # Implementations that do not support hostname validation
LIMBO_JSON = data/limbo.json
LIBFAKETIME = /usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1

# Targets for performance benchmarking (Eval 1)
PERF_TARGETS = \
	chrome verdict-chrome-aws-lc verdict-chrome \
	firefox verdict-firefox-aws-lc verdict-firefox \
	openssl verdict-openssl-aws-lc verdict-openssl \
	armor ceres \
	hammurabi-chrome hammurabi-firefox
PERF_REPEAT = 10
PERF_JOBS = 1
PERF_SAMPLE = 1

# Targets for differential testing (Eval 2)
DIFF_TARGETS = \
	chrome verdict-chrome \
	firefox verdict-firefox \
	openssl verdict-openssl
DIFF_JOBS = $(shell nproc)
DIFF_SAMPLE = 1

END_TO_END_TIME = 2025-01-16 12:00:00
END_TO_END_DELAY = 5ms
END_TO_END_WARMUP = 20
END_TO_END_REPEAT = 100

# Settings for reducing noise (need to be changed on the test machine)
ISOLATE_CORES = # e.g. 0,2,4,6
CORE_FREQUENCY = # e.g. 2401000

# Additional flags (for verdict frontend)
VERDICT_FLAGS =

.PHONY: main
main:
	@echo "Please see README for the usage of this Makefile"

# Run all evaluations
.PHONY: eval
eval: eval-1 eval-2 eval-3

# Test that all evals work correctly with a
# parallel and potentially noisy configuration
.PHONY: test
test: PERF_REPEAT = 1
test: PERF_JOBS = $(shell nproc)
test: END_TO_END_DELAY = 1ms
test: END_TO_END_WARMUP = 0
test: END_TO_END_REPEAT = 2
test: eval-1 eval-2 eval-3

.PHONY: figures
figures: eval-1 eval-2 eval-3

#############################################
# ███████╗██╗   ██╗ █████╗ ██╗          ██╗ #
# ██╔════╝██║   ██║██╔══██╗██║         ███║ #
# █████╗  ██║   ██║███████║██║         ╚██║ #
# ██╔══╝  ╚██╗ ██╔╝██╔══██║██║          ██║ #
# ███████╗ ╚████╔╝ ██║  ██║███████╗     ██║ #
# ╚══════╝  ╚═══╝  ╚═╝  ╚═╝╚══════╝     ╚═╝ #
#############################################
.PHONY: eval-1
eval-1: results $(foreach target,$(PERF_TARGETS),results/perf-$(target).csv)
	@echo "%%%%%%%%%%%%%%%%%%%%%%%"
	@echo "% Performance results %"
	@echo "%%%%%%%%%%%%%%%%%%%%%%%"
	@scripts/perf_results -r results -o results/performance.pdf

# Reduce benchmark size for some implementations
results/perf-armor.csv: PERF_SAMPLE = 0.001
results/perf-ceres.csv: PERF_SAMPLE = 0.001
results/perf-hammurabi-chrome.csv: PERF_SAMPLE = 0.01
results/perf-hammurabi-firefox.csv: PERF_SAMPLE = 0.01

results/perf-%.csv:
	$(if $(ISOLATE_CORES),taskset -c $(ISOLATE_CORES),) \
	$(if $(filter %-aws-lc,$*),$(VERDICT_AWS_LC),$(VERDICT)) bench-ct-logs \
		$(patsubst %-aws-lc,%,$*) \
		$(ROOTS) $(CT_LOG_INTS) $(CT_LOG_TESTS) \
		-t $(CT_LOG_TIMESTAMP) -n $(PERF_REPEAT) -j $(PERF_JOBS) \
		--sample $(PERF_SAMPLE) \
		--bench-repo . \
		$(if $(filter $(NO_DOMAIN),$*),--no-domain,) \
		$(VERDICT_FLAGS) \
		-o results/perf-$*.tmp.csv
	mv results/perf-$*.tmp.csv results/perf-$*.csv

#################################################
# ███████╗██╗   ██╗ █████╗ ██╗         ██████╗  #
# ██╔════╝██║   ██║██╔══██╗██║         ╚════██╗ #
# █████╗  ██║   ██║███████║██║          █████╔╝ #
# ██╔══╝  ╚██╗ ██╔╝██╔══██║██║         ██╔═══╝  #
# ███████╗ ╚████╔╝ ██║  ██║███████╗    ███████╗ #
# ╚══════╝  ╚═══╝  ╚═╝  ╚═╝╚══════╝    ╚══════╝ #
#################################################

.PHONY: eval-2
eval-2: limbo diff
	@echo
	@echo "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
	@echo "% Differential test results %"
	@echo "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
	@python3 scripts/diff_results.py

# Run all Limbo tests
.PHONY: limbo
limbo: results $(foreach target,$(DIFF_TARGETS),results/limbo-$(target).csv)

# Run all differential tests (on CT logs)
.PHONY: diff
diff: results $(foreach target,$(DIFF_TARGETS),results/diff-$(target).csv)

# x509-limbo test command
results/limbo-%.csv:
	$(VERDICT) limbo $* $(LIMBO_JSON) \
		-j $(DIFF_JOBS) \
		--bench-repo . \
		$(VERDICT_FLAGS) > results/limbo-$*.tmp.csv
	mv results/limbo-$*.tmp.csv results/limbo-$*.csv

results/diff-%.csv:
	$(VERDICT) bench-ct-logs $* \
		$(ROOTS) $(CT_LOG_INTS) $(CT_LOG_TESTS) \
		-t $(CT_LOG_TIMESTAMP) -n 1 -j $(DIFF_JOBS) \
		--sample $(DIFF_SAMPLE) \
		--bench-repo . \
		$(if $(filter $(NO_DOMAIN),$*),--no-domain,) \
		$(VERDICT_FLAGS) \
		-o results/diff-$*.tmp.csv
	mv results/diff-$*.tmp.csv results/diff-$*.csv

#################################################
# ███████╗██╗   ██╗ █████╗ ██╗         ██████╗  #
# ██╔════╝██║   ██║██╔══██╗██║         ╚════██╗ #
# █████╗  ██║   ██║███████║██║          █████╔╝ #
# ██╔══╝  ╚██╗ ██╔╝██╔══██║██║          ╚═══██╗ #
# ███████╗ ╚████╔╝ ██║  ██║███████╗    ██████╔╝ #
# ╚══════╝  ╚═══╝  ╚═╝  ╚═╝╚══════╝    ╚═════╝  #
#################################################

.PHONY: eval-3
eval-3: results results/end-to-end-aws-lc.csv results/end-to-end-libcrux.csv
	@echo
	@echo "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
	@echo "% End-to-end HTTPS performance %"
	@echo "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
	@python3 scripts/rustls_results.py \
		results/end-to-end-aws-lc.csv \
		results/end-to-end-libcrux.csv

# Run end-to-end tests with Rustls
# Adding `.NOTPARALLEL` since parallel commands of tc might conflict
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

##################################
# ███╗   ███╗██╗███████╗ ██████╗ #
# ████╗ ████║██║██╔════╝██╔════╝ #
# ██╔████╔██║██║███████╗██║      #
# ██║╚██╔╝██║██║╚════██║██║      #
# ██║ ╚═╝ ██║██║███████║╚██████╗ #
# ╚═╝     ╚═╝╚═╝╚══════╝ ╚═════╝ #
##################################

results:
	mkdir -p results

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

# Install dependencies and build Verdict (should be run inside the Docker container)
.PHONY: build-verdict
build-verdict: SHELL := /bin/bash
build-verdict:
	apt update && apt install -y curl unzip gcc git
	curl https://sh.rustup.rs -sSf | sh -s -- -y
	. "$$HOME/.cargo/env" && \
	cd verdict && \
	. tools/activate.sh && \
	vargo build

# Compare results with the reference
# Used for CI testing
.PHONY: compare-ref
compare-ref: PERF_REPEAT = 1
compare-ref: PERF_JOBS = $(shell nproc)
compare-ref: ref-results results \
		$(foreach target,$(PERF_TARGETS),results/perf-$(target).csv) \
		$(foreach target,$(DIFF_TARGETS),results/diff-$(target).csv) \
		$(foreach target,$(DIFF_TARGETS),results/limbo-$(target).csv)
	
	@echo "%%% Comparing performance results with reference"; \
	for target in $(PERF_TARGETS); do \
		echo "Comparing results/perf-$$target.csv with ref-results/perf-$$target.csv"; \
		$(VERDICT) diff-results \
			ref-results/perf-$$target.csv \
			results/perf-$$target.csv | grep -E "mismatch|does not exist" && exit 1; \
		true; \
	done

	@echo; echo "%%% Comparing differential testing results with reference"; \
	for target in $(DIFF_TARGETS); do \
		echo "Comparing results/diff-$$target.csv with ref-results/diff-$$target.csv"; \
		$(VERDICT) diff-results \
			ref-results/diff-$$target.csv \
			results/diff-$$target.csv | grep -E "mismatch|does not exist" && exit 1; \
		$(VERDICT) diff-results \
			ref-results/limbo-$$target.csv \
			results/limbo-$$target.csv | grep -E "mismatch|does not exist" && exit 1; \
		true; \
	done
