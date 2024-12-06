##########################################################################
### Makefile to compile Verus project with external cargo dependencies ###
##########################################################################

# Uses these variables (for example):
#   NAME = Name of the crate (e.g. vpl, parser)
#   TYPE = type of the crate (lib/bin)
#   SOURCE = All source files used for monitoring changes (e.g. $(wildcard src/*.rs) $(wildcard src/*.pl))
#   CARGO_DEPS = Rust dependencies added with `cargo add` (e.g. peg clap thiserror tempfile)
#   VERUS_DEPS = Verus dependency paths (e.g. vest). For each dep in VERUS_DEPS, we expect $(dep).rlib and $(dep).verusdata to exist

EXEC_MAIN = src/main.rs
LIB_MAIN = src/lib.rs

# Recursive wildcard from https://stackoverflow.com/questions/2483182/recursive-wildcards-in-gnu-make/18258352#18258352
rwildcard=$(foreach d,$(wildcard $(1:=/*)),$(call rwildcard,$d,$2) $(filter $(subst *,%,$2),$d))

SOURCE = $(call rwildcard,src,*.rs)

.PHONY: debug
debug: verify
	cargo build

.PHONY: release
release: verify
	cargo build --release

.PHONY: verify
verify: target/verify/$(NAME).verusdata

.PHONY: test
test: $(TEST_TARGETS)
	cargo test

.PHONY: verify-deps
verify-deps:
# Generate meta data for Rust dependencies
	@set -e; \
	for dep in $(CARGO_DEPS); do \
		cargo build --profile=verify --package=$$dep; \
    done

# For each $dep in VERUS_DEPS, generate a rule to compile target/$dep.verusdata
define DEP_TEMPLATE
../$1/target/verify/$1.verusdata: $$(call rwildcard,../$1/src,*.rs)
	@echo "### Verifying Verus dependency $1 (../$1)"
	cd ../$1 && make target/verify/$1.verusdata
endef
$(foreach dep,$(VERUS_DEPS),$(eval $(call DEP_TEMPLATE,$(dep))))

# NOTE: target/$(NAME).verusdata and target/$(NAME).rlib generated
# by this rule is only supposed to be used for verification purposes
# Use `cargo build` to build the crate for execution.
#
# Each dependency <dep> in CARGO_DEPS is mapped to verus argument --extern <dep>=target/verify/lib<dep>.<rlib|dylib|...>
# Each dependency <dep> in VERUS_DEPS is mapped to verus argument
#     --extern <dep>=../<dep>/target/verify/lib<dep>.rlib
#     --import <dep>=../<dep>/target/verify/<dep>.verusdata
target/verify/$(NAME).verusdata: $(SOURCE) verify-deps $(foreach dep,$(VERUS_DEPS),../$(dep)/target/verify/$(dep).verusdata)
	mkdir -p target/verify
	verus $(if $(filter lib,$(TYPE)),$(LIB_MAIN),$(EXEC_MAIN)) \
		--crate-name $(NAME) \
		$(if $(filter lib,$(TYPE)),--crate-type=lib,) \
		-L dependency=target/verify/deps \
		$(foreach dep,$(VERUS_DEPS),-L dependency=../$(dep)/target/verify/deps) \
		$(foreach dep,$(VERUS_DEPS),-L dependency=../$(dep)/target/verify) \
		$(foreach dep,$(CARGO_DEPS),--extern $(subst -,_,$(dep))=$(firstword \
			$(wildcard target/verify/lib$(subst -,_,$(dep)).rlib) \
			$(wildcard target/verify/lib$(subst -,_,$(dep)).so) \
			$(wildcard target/verify/lib$(subst -,_,$(dep)).dylib) \
			$(wildcard target/verify/lib$(subst -,_,$(dep)).rmeta))) \
		$(foreach dep,$(VERUS_DEPS), \
			--extern $(dep)=$(firstword $(wildcard ../$(dep)/target/verify/lib$(dep).rlib)) \
			--import $(dep)=../$(dep)/target/verify/$(dep).verusdata) \
		--export target/verify/$(NAME).verusdata \
		--compile -o target/verify/lib$(NAME).rlib \
		$(VERUS_FLAGS)

.PHONY: clean
clean:
	cargo clean
