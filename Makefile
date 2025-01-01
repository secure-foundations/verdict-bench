CC = gcc
SOURCE = cert_bench.c
TARGET = cert_bench
JOBS := $(patsubst -j%,%,$(filter -j%,$(MAKEFLAGS)))

.PHONY: release
release: openssl/libcrypto.a openssl/libssl.a
	$(CC) -o $(TARGET) -I openssl/include $(SOURCE) \
		-Lopenssl -lcrypto -lssl \
		-Wl,-rpath,openssl

openssl/libcrypto.a openssl/libssl.a &:
	git submodule update --init
	cd openssl && ./Configure && make -j $(JOBS)

.PHONY: clean
clean:
	rm -rf $(TARGET)

.PHONY: clean-openssl
clean-openssl:
	cd openssl && make clean
