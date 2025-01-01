
.PHONY: release
release:
	cd prolog && make
	cargo build --release
