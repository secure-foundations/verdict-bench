NAME = parser
TARGETS = parser libparser.rlib

CARGO_DEPS = der base64 paste macros
VERUS_DEPS = vest polyfill
VERUS_FLAGS = --rlimit 50

include ../dep.mk

# Same as debug but with parser trace enabled
debug-trace: VERUS_FLAGS += --cfg parser_trace
debug-trace: debug
