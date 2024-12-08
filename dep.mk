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

CARGO_DEPS_SANITIZED = $(subst -,_,$(CARGO_DEPS))
VERUS_DEPS_SANITIZED = $(subst -,_,$(VERUS_DEPS))

# Do no delete intermediate files
.SECONDARY:

.PHONY: debug
debug: target/debug/verify/$(NAME).verusdata
	cargo build

.PHONY: release
release: target/release/verify/$(NAME).verusdata
	cargo build --release

.PHONY: test
test: $(TEST_TARGETS)
	cargo test

.PHONY: build-cargo-deps-%
build-cargo-deps-%:
# Generate meta data for Rust dependencies
	@set -e; \
	for dep in $(CARGO_DEPS); do \
		cmd="cargo build $(if $(filter release,$*),--release,) --package=$$dep"; \
		echo "$$cmd"; \
		$$cmd; \
    done

# For each $dep in VERUS_DEPS_SANITIZED, generate a rule to compile target/$dep.verusdata
define DEP_TEMPLATE
../$1/target/%/verify/lib$1.rlib: $(foreach dep,$(VERUS_DEPS_SANITIZED),$$(call rwildcard,../$(dep)/src,*.rs))
	@echo "### Verifying Verus dependency $1 (../$1)"
	cd ../$1 && make target/$$*/verify/lib$1.rlib
endef
$(foreach dep,$(VERUS_DEPS_SANITIZED),$(eval $(call DEP_TEMPLATE,$(dep))))

define VERUS_COMMAND
verus $(if $(filter lib,$(TYPE)),$(LIB_MAIN),$(EXEC_MAIN)) \
	--crate-name $(NAME) \
	$(if $(filter lib,$(TYPE)),--crate-type=lib,) \
	-L dependency=target/$1/deps \
	$(foreach dep,$(VERUS_DEPS_SANITIZED),-L dependency=../$(dep)/target/$1/deps) \
	$(foreach dep,$(VERUS_DEPS_SANITIZED),-L dependency=../$(dep)/target/$1/verify) \
	$(foreach dep,$(CARGO_DEPS_SANITIZED),--extern $(dep)=$(shell \
		find target/$1/lib$(dep).rlib \
		     target/$1/lib$(dep).so \
			 target/$1/lib$(dep).dylib 2>/dev/null | head -n1)) \
	$(foreach dep,$(VERUS_DEPS_SANITIZED), \
		--extern $(dep)=../$(dep)/target/$1/verify/lib$(dep).rlib \
		--import $(dep)=../$(dep)/target/$1/verify/$(dep).verusdata) \
	$(VERUS_FLAGS)
endef

# NOTE: target/$(NAME).verusdata and target/$(NAME).rlib generated
# by this rule is only supposed to be used for verification purposes
# Use `cargo build` to build the crate for execution.
#
# Each dependency <dep> in CARGO_DEPS_SANITIZED is mapped to verus argument --extern <dep>=target/<profile>/lib<dep>.<rlib|dylib|...>
# Each dependency <dep> in VERUS_DEPS_SANITIZED is mapped to verus argument
#     --extern <dep>=../<dep>/target/<profile>/verify/lib<dep>.rlib
#     --import <dep>=../<dep>/target/<profile>/verify/<dep>.verusdata
target/%/verify/$(NAME).verusdata: $(SOURCE) build-cargo-deps-% $(foreach dep,$(VERUS_DEPS_SANITIZED),../$(dep)/target/%/verify/lib$(dep).rlib)
	mkdir -p target/$*/verify
	$(call VERUS_COMMAND,$*) --export target/$*/verify/$(NAME).verusdata

target/%/verify/lib$(NAME).rlib: $(SOURCE) build-cargo-deps-% $(foreach dep,$(VERUS_DEPS_SANITIZED),../$(dep)/target/%/verify/lib$(dep).rlib)
	mkdir -p target/$*/verify
	$(call VERUS_COMMAND,$*) \
		--export target/$*/verify/$(NAME).verusdata \
		--compile -o target/$*/verify/lib$(NAME).rlib

.PHONY: clean
clean:
	cargo clean
