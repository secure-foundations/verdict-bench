DOCKER = sudo docker
DOCKER_IMAGE_TAG = chrome-build

CHROMIUM_REPO = https://chromium.googlesource.com/chromium/src.git
CHROMIUM_COMMIT = 0590dcf7b036e15c133de35213be8fe0986896aa

CURRENT_DIR = $(shell pwd)
DIFF_FILE = cert_bench.diff

TARGET = cert_bench

.PHONY: release
release: build-env
	$(DOCKER) run -it --init \
		-v $(CURRENT_DIR):/build/local \
		$(DOCKER_IMAGE_TAG) \
		make src/out/Release/$(TARGET)

.PHONY: debug
debug: build-env
	$(DOCKER) run -it --init \
		-v $(CURRENT_DIR):/build/local \
		$(DOCKER_IMAGE_TAG) \
		make src/out/Debug/$(TARGET)

.PHONY: build-env
build-env:
	$(DOCKER) build . -t $(DOCKER_IMAGE_TAG)

.PHONY: enter
enter:
	$(DOCKER) run -it --init \
		-v $(CURRENT_DIR):/build/local \
		$(DOCKER_IMAGE_TAG)

.PHONY: clean
clean:
	$(DOCKER) run -it --init \
		-v $(CURRENT_DIR):/build/local \
		$(DOCKER_IMAGE_TAG) \
		make inner-clean

##### Targets below are executed within Docker #####

%.diff:
	cd src && git diff --staged > ../$*.diff

# Fetch Chromium source and apply our changes (${DIFF_FILE})
src/.fetched:
	@set -e; \
	mkdir -p src; \
	cd src; \
	if ! [ -f .init ]; then \
		echo "### checking out chromium@${CHROMIUM_COMMIT}"; \
		rm -rf .git; \
		git init; \
		git remote add origin ${CHROMIUM_REPO}; \
		git config --local extensions.partialClone origin; \
		git fetch --progress --depth 1 --filter=blob:none origin ${CHROMIUM_COMMIT}; \
		git checkout FETCH_HEAD; \
		touch .init; \
	fi; \
	echo "### applying gclient sync"; \
	git apply ../deps.diff; \
	gclient sync --no-history --shallow -j8; \
	git apply ../${DIFF_FILE}; \
	touch .fetched; \
	echo "### fetched chromium@${CHROMIUM_COMMIT}"

src/out/Debug/%: src/.fetched force
	[ -f "src/out/Debug/build.ninja" ] || (cd src && gn gen out/Debug --args"build_dawn_tests=false use_ozone=false use_x11=false use_aura=false")
	cd src && autoninja -C out/Debug $*

src/out/Release/%: src/.fetched force
	[ -f "src/out/Release/build.ninja" ] || (cd src && gn gen out/Release --args="is_component_build=false is_debug=false build_dawn_tests=false use_ozone=false use_x11=false use_aura=false")
	cd src && autoninja -C out/Release $*

.PHONY: force
force:
