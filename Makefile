DOCKER = sudo docker
DOCKER_IMAGE_TAG = verdict-bench-build
DOCKER_FLAGS = --privileged

VERUS=verus/source/target-verus/release/verus
VERUSC=verdict/tools/verusc/target/release/verusc

DEPS = armor ceres openssl hammurabi chromium firefox

CURRENT_DIR = $(shell pwd)

# Build Verdict with the vendored version of verus
.PHONY: verdict
verdict: $(VERUS) $(VERUSC)
	cd verdict && \
	PATH="$(dir $(realpath $(VERUS))):$$PATH" \
	RUSTC_WRAPPER="$(realpath $(VERUSC))" cargo build --release

$(VERUSC):
	cd verdict/tools/verusc && cargo build --release

# Verus build currently only supports Bash
$(VERUS): SHELL = /bin/bash
$(VERUS):
	cd verus/source && \
	./tools/get-z3.sh && \
	source ../tools/activate && \
	vargo build --release

# Build all other X.509 implementations in the docker environment
.PHONY: deps
deps: build-env submodules
	$(DOCKER) run -it --init \
		$(DOCKER_FLAGS) \
		-v $(CURRENT_DIR):$(CURRENT_DIR) \
		-w $(CURRENT_DIR) \
		$(DOCKER_IMAGE_TAG) \
		make inner-deps HOST_USER=$(shell id -u)

.PHONY: dep-%
dep-%: build-env submodules
	$(DOCKER) run -it --init \
		$(DOCKER_FLAGS) \
		-v $(CURRENT_DIR):$(CURRENT_DIR) \
		-w $(CURRENT_DIR) \
		$(DOCKER_IMAGE_TAG) \
		make inner-dep-$* HOST_USER=$(shell id -u)

.PHONY: submodules
submodules:
	git submodule update --init --recursive

.PHONY: build-env
build-env:
	$(DOCKER) build . -t $(DOCKER_IMAGE_TAG)

.PHONY: enter
enter: build-env
	$(DOCKER) run -it --init \
		$(DOCKER_FLAGS) \
		-v $(CURRENT_DIR):$(CURRENT_DIR) \
		-w $(CURRENT_DIR) \
		$(DOCKER_IMAGE_TAG)

##### Targets below are executed within Docker #####

.PHONY: inner-deps
inner-deps: $(foreach dep,$(DEPS),inner-dep-$(dep))

.PHONY: inner-dep-%
inner-dep-%:
	chown -R $$(whoami) $*
	cd $* && make
	chown -R $(HOST_USER) $*
