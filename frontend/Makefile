NAME = frontend
TARGETS = frontend

CARGO_DEPS = macros clap thiserror csv serde serde_json chrono regex crossbeam tempfile limbo-harness-support rand
VERUS_DEPS = parser polyfill vest chain rspec_lib
TEST_TARGETS =
VERUS_FLAGS = --no-lifetime

TEST_TARGETS = test-policy-chrome-hammurabi test-policy-firefox-hammurabi test-policy-open-ssl
TEST_TIME = 1725029869

include ../dep.mk

DOMAINS = github.com google.com outlook.com slack.com verus.rs

.PHONY: test-policy-%
test-policy-%: debug
# For each domain in DOMAINS, remove the suffix, then find the corresponding pem
	@set -e; \
	for domain in $(DOMAINS); do \
		pem_file=tests/chains/$${domain%%.*}.pem; \
		if [ "$*" = "open-ssl" ]; then \
			cmd="target/debug/frontend validate $* tests/roots.pem $$pem_file -t $(TEST_TIME) -s"; \
		else \
			cmd="target/debug/frontend validate $* tests/roots.pem $$pem_file $$domain -t $(TEST_TIME) -s"; \
		fi; \
		echo $$cmd; \
		printf "[$*] $$domain: "; \
		$$cmd; \
	done
