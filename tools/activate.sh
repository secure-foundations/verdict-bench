# Usage: source this script at the root of the repo

# Similar to how Verus's internal vargo would work
# https://github.com/verus-lang/verus/blob/main/tools/activate

unset -f cargo 2>/dev/null || true
unset -f vargo 2>/dev/null || true

REPO_ROOT=$(pwd)
REAL_CARGO="$(which cargo)"

git submodule update --init

# Build verus
(cd deps/verus/source &&
[ -f z3 ] || ./tools/get-z3.sh &&
source ../tools/activate &&
vargo build --release) || return 1

# Build verusc
(cd "tools/verusc" && cargo build --release) || return 1

vargo() {
    RUSTC_WRAPPER="$REPO_ROOT/tools/verusc/target/release/verusc" "$REAL_CARGO" "$@"
}

cargo() {
    echo You have activated the build environment of Verus, so it is likely that
    echo you want to use \`vargo\` instead of \`cargo\`. Restart the shell to disable.
}

export PATH="$REPO_ROOT/deps/verus/source/target-verus/release:$PATH"
