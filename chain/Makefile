NAME = chain
TARGETS = libchain.rlib

CARGO_DEPS = macros libcrux libcrux-hacl chrono aws-lc-rs rspec
VERUS_DEPS = parser polyfill vest rspec_lib

# Temporary fix for https://github.com/verus-lang/verus/issues/1288
# TODO: this skips the lifetime check for proof-mode code
VERUS_FLAGS = --no-lifetime --rlimit 50

# LTO = true

include ../dep.mk
