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

# Do no delete intermediates
.SECONDARY:

.PHONY: debug
debug: target/debug/$(NAME).verusdata
	cargo build

.PHONY: release
release: target/release/$(NAME).verusdata
	cargo build --release

.PHONY: test
test: $(TEST_TARGETS)
	cargo test

.PHONY: verify-deps-%
verify-deps-%:
# Generate meta data for Rust dependencies
	@set -e; \
	for dep in $(CARGO_DEPS); do \
		cmd="cargo build $(if $(filter release,$*),--release,) --package=$$dep"; \
		echo "$$cmd"; \
		$$cmd; \
    done

# For each $dep in VERUS_DEPS, generate a rule to compile target/$dep.verusdata
define DEP_TEMPLATE
../$1/target/%/lib$1.rlib: $$(call rwildcard,../$1/src,*.rs)
	@echo "### Verifying Verus dependency $1 (../$1)"
	cd ../$1 && make target/$$*/lib$1.rlib
endef
$(foreach dep,$(VERUS_DEPS),$(eval $(call DEP_TEMPLATE,$(dep))))

define VERUS_COMMAND
verus $(if $(filter lib,$(TYPE)),$(LIB_MAIN),$(EXEC_MAIN)) \
	--crate-name $(NAME) \
	$(if $(filter lib,$(TYPE)),--crate-type=lib,) \
	-L dependency=target/$1/deps \
	$(foreach dep,$(VERUS_DEPS),-L dependency=../$(dep)/target/$1/deps) \
	$(foreach dep,$(VERUS_DEPS),-L dependency=../$(dep)/target/$1) \
	$(foreach dep,$(CARGO_DEPS),--extern $(subst -,_,$(dep))=$(firstword \
		$(wildcard target/$1/lib$(subst -,_,$(dep)).rlib) \
		$(wildcard target/$1/lib$(subst -,_,$(dep)).so) \
		$(wildcard target/$1/lib$(subst -,_,$(dep)).dylib) \
		$(wildcard target/$1/lib$(subst -,_,$(dep)).rmeta))) \
	$(foreach dep,$(VERUS_DEPS), \
		--extern $(dep)=$(firstword $(wildcard ../$(dep)/target/$1/lib$(dep).rlib)) \
		--import $(dep)=../$(dep)/target/$1/$(dep).verusdata) \
	$(VERUS_FLAGS)
endef

# NOTE: target/$(NAME).verusdata and target/$(NAME).rlib generated
# by this rule is only supposed to be used for verification purposes
# Use `cargo build` to build the crate for execution.
#
# Each dependency <dep> in CARGO_DEPS is mapped to verus argument --extern <dep>=target/<profile>/lib<dep>.<rlib|dylib|...>
# Each dependency <dep> in VERUS_DEPS is mapped to verus argument
#     --extern <dep>=../<dep>/target/<profile>/lib<dep>.rlib
#     --import <dep>=../<dep>/target/<profile>/<dep>.verusdata
target/%/$(NAME).verusdata: $(SOURCE) verify-deps-% $(foreach dep,$(VERUS_DEPS),../$(dep)/target/%/lib$(dep).rlib)
	mkdir -p target/$*
	$(call VERUS_COMMAND,$*) --export target/$*/$(NAME).verusdata

target/%/lib$(NAME).rlib: $(SOURCE) verify-deps-% $(foreach dep,$(VERUS_DEPS),../$(dep)/target/%/lib$(dep).rlib)
	mkdir -p target/$*
	$(call VERUS_COMMAND,$*) \
		--export target/$*/$(NAME).verusdata \
		--compile -o target/$*/lib$(NAME).rlib

.PHONY: clean
clean:
	cargo clean
