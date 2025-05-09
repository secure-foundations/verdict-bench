# Usage: source this script at the root of the repo

# Similar to how Verus's internal vargo would work
# https://github.com/verus-lang/verus/blob/main/tools/activate

unset -f cargo 2>/dev/null || true
unset -f vargo 2>/dev/null || true

REPO_ROOT=$(pwd)
REAL_CARGO="$(which cargo)"

# Clone https://github.com/zhengyao-lin/verus.git into deps/verus
if [ ! -d deps/verus ]; then
    (git init deps/verus &&
    cd deps/verus &&
    git remote add origin https://github.com/zhengyao-lin/verus.git &&
    git fetch --depth 1 origin df8335e469b7c091d16538f263536c602fa5d936 &&
    git checkout FETCH_HEAD) || return 1
fi

# Build verus
(cd deps/verus/source &&
rustup toolchain install &&
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
