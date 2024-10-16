NAME = chain
TARGETS = chain libchain.rlib

CARGO_DEPS = macros base64 clap thiserror libcrux libcrux-hacl chrono aws-lc-rs
VERUS_DEPS = parser polyfill vest vpl
TEST_TARGETS = test-policy-chrome test-policy-firefox

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
		(target/debug/chain tests/policies/$*.pl tests/roots.pem $$pem_file $$domain 1>&2 2>/dev/null && echo "success") \
		|| (echo "failed"; exit 1); \
	done
