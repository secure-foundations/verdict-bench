.PHONY: build
build: src/armor-agda/src/Main
	cd src/armor-driver && ./install.sh

src/armor-agda/src/Main: agda/agda
	cd src/armor-agda && ./compile.sh

agda/agda:
	git submodule update --init
	cd agda && stack build --stack-yaml stack-8.8.4.yaml
