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
	if [ -d .git ] && [ "$$(git rev-parse HEAD)" = "${CHROMIUM_COMMIT}" ]; then \
		touch .fetched; \
		echo "### chromium@${CHROMIUM_COMMIT} already fetched"; \
	else \
		git init; \
		git remote add origin ${CHROMIUM_REPO}; \
		git fetch --depth 1 origin ${CHROMIUM_COMMIT}; \
		git checkout FETCH_HEAD; \
		gclient sync --no-history; \
		git apply ../${DIFF_FILE}; \
		touch .fetched; \
		echo "### fetched chromium@${CHROMIUM_COMMIT}"; \
	fi

src/out/Debug/%: src/.fetched force
	[ -f "src/out/Debug/build.ninja" ] || (cd src && gn gen out/Debug)
	cd src && autoninja -C out/Debug $*

src/out/Release/%: src/.fetched force
	[ -f "src/out/Release/build.ninja" ] || (cd src && gn gen out/Release --args="is_debug=false")
	cd src && autoninja -C out/Release $*

.PHONY: force
force:
