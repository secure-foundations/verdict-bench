.PHONY: build
build: src/armor-agda/src/Main
	cd src/armor-driver && ./install.sh
	cp src/armor-agda/src/Main src/armor-driver/armor-bin

src/armor-agda/src/Main: agda/agda
	cd src/armor-agda && PATH="$(realpath agda):$$PATH" ./compile.sh

agda/agda:
	git submodule update --init
	cd agda && stack install --stack-yaml stack-8.8.4.yaml --install-path .
