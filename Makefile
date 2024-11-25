CC = gcc
SOURCE = cert_bench.c
TARGET = cert_bench
CFLAGS = -O2 -lcrypto -lssl

.PHONY: release
release:
	$(CC) -o $(TARGET) $(SOURCE) $(CFLAGS)

.PHONY: clean
clean:
	rm -rf $(TARGET)
