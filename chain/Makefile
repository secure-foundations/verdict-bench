NAME = chain
TARGETS = chain libchain.rlib

CARGO_DEPS = macros base64 clap thiserror libcrux libcrux-hacl chrono aws-lc-rs rspec
VERUS_DEPS = parser polyfill vest rspec_lib
TEST_TARGETS = test-policy-chrome # test-policy-firefox
TEST_TIME = 1725029869

# Temporary fix for https://github.com/verus-lang/verus/issues/1288
# TODO: this skips the lifetime check for proof-mode code
VERUS_FLAGS = --no-lifetime --rlimit 50

include ../dep.mk

DOMAINS = github.com google.com outlook.com slack.com verus.rs

.PHONY: test-policy-%
test-policy-%: target/debug/chain
# For each domain in DOMAINS, remove the suffix, then find the corresponding pem
	@for domain in $(DOMAINS); do \
		pem_file=tests/chains/$${domain%%.*}.pem; \
		printf "[$*] $$domain: "; \
		echo "target/debug/chain $*-hammurabi tests/roots.pem $$pem_file $$domain -t $(TEST_TIME) -s"; \
		(target/debug/chain \
			$*-hammurabi \
			tests/roots.pem \
			$$pem_file \
			$$domain \
			-t $(TEST_TIME) \
			-s) \
		|| (echo "failed"; exit 1); \
	done
