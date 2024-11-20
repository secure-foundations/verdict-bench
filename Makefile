DOCKER = sudo docker
DOCKER_IMAGE_TAG = firefox-build

FIREFOX_CHANGESET = dbd5ee74c531204784baa6a81961ed556783ea15

CURRENT_DIR = $(shell pwd)
DIFF_FILE = remove_builtin_roots.diff

.PHONY: release
release: build-env
	$(DOCKER) run -it --init \
		-v $(CURRENT_DIR):/build/local \
		$(DOCKER_IMAGE_TAG) \
		make src

.PHONY: build-env
build-env:
	$(DOCKER) build . -t $(DOCKER_IMAGE_TAG)

.PHONY: enter
enter: build-env
	$(DOCKER) run -it --init \
		-v $(CURRENT_DIR):/build/local \
		$(DOCKER_IMAGE_TAG)

.PHONY: build
build: build-env
	$(DOCKER) run -it --init \
		-v $(CURRENT_DIR):/build/local \
		$(DOCKER_IMAGE_TAG) \
		make inner-build

.PHONY: clean
clean: build-env
	$(DOCKER) run -it --init \
		-v $(CURRENT_DIR):/build/local \
		$(DOCKER_IMAGE_TAG) \
		make inner-clean

.PHONY: xpcshell
xpcshell: build-env
	$(DOCKER) run -it --init \
		-v $(CURRENT_DIR):/build/local \
		$(DOCKER_IMAGE_TAG) \
		bash -c "LD_LIBRARY_PATH=/build/local/mozilla-unified/obj-x86_64-pc-linux-gnu/dist/bin:$$LD_LIBRARY_PATH \
			mozilla-unified/obj-x86_64-pc-linux-gnu/dist/bin/xpcshell"

##### Targets below are executed within Docker #####

.PHONY: src
src: mozilla-unified/.fetched

mozilla-unified/.fetched:
	GECKO_HEAD_REV=$(FIREFOX_CHANGESET) python3 bootstrap.py --no-interactive
	cd mozilla-unified && hg import ../$(DIFF_FILE) --no-commit
	touch mozilla-unified/.fetched

# mozilla-unified/.bootstrapped: mozilla-unified/.fetched
# # echo 2 for "Firefox for Desktop"; and then yes for default actions
# 	cd mozilla-unified && (echo 2; yes) | SHELL=/bin/bash MACH_USE_SYSTEM_PYTHON=1 ./mach bootstrap
# 	touch mozilla-unified/.bootstrapped

.PHONY: inner-build
inner-build: src
	cd mozilla-unified && \
	. ~/.bashrc && \
	SHELL=/bin/bash MACH_USE_SYSTEM_PYTHON=1 ./mach build

.PHONY: inner-clean
inner-clean: src
	cd mozilla-unified && \
	. ~/.bashrc && \
	SHELL=/bin/bash MACH_USE_SYSTEM_PYTHON=1 ./mach clobber
