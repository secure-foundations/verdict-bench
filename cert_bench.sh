#!/bin/bash
# After Firefox is compiled (`make build`), use this script to run cert_bench.js

set -e

SCRIPT_DIR="$(dirname "$(realpath $0)")"
MOZILLA="$(realpath $SCRIPT_DIR/mozilla-unified)"
DIST_BIN="$MOZILLA/obj-firefox/dist/bin"
XPCSHELL="$DIST_BIN/run-mozilla.sh $DIST_BIN/xpcshell"

roots=$1
shift 1

exec $XPCSHELL "$SCRIPT_DIR/cert_bench.js" $(realpath $roots) "$@"
