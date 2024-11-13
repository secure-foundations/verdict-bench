NAME = frontend
TARGETS = frontend

CARGO_DEPS = macros base64 clap thiserror csv serde chrono regex crossbeam cpu-time heappy
VERUS_DEPS = parser polyfill vest chain rspec_lib
TEST_TARGETS =
VERUS_FLAGS = --no-lifetime

TEST_TARGETS = test-policy-chrome test-policy-firefox
TEST_TIME = 1725029869

include ../dep.mk

DOMAINS = github.com google.com outlook.com slack.com verus.rs

.PHONY: test-policy-%
test-policy-%: target/debug/frontend
# For each domain in DOMAINS, remove the suffix, then find the corresponding pem
	@set -e; \
	for domain in $(DOMAINS); do \
		pem_file=tests/chains/$${domain%%.*}.pem; \
		cmd="target/debug/frontend validate $*-hammurabi tests/roots.pem $$pem_file $$domain -t $(TEST_TIME) -s"; \
		echo $$cmd; \
		printf "[$*] $$domain: "; \
		$$cmd; \
	done
