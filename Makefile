DOCKER = sudo docker
DOCKER_IMAGE_TAG = verdict-bench-build

DEPS = armor ceres openssl hammurabi chromium firefox

CURRENT_DIR = $(shell pwd)

.PHONY: deps
deps: build-env submodules
	$(DOCKER) run -it --init \
		-v $(CURRENT_DIR):$(CURRENT_DIR) \
		-w $(CURRENT_DIR) \
		$(DOCKER_IMAGE_TAG) \
		make inner-deps HOST_USER=$(shell id -u)

.PHONY: dep-%
dep-%: build-env submodules
	$(DOCKER) run -it --init \
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
