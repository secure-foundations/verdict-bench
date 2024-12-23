# Similar to how Verus's internal vargo would work
# https://github.com/verus-lang/verus/blob/main/tools/activate

unset -f cargo 2>/dev/null || true

if [ "$BASH_VERSION" ]; then
    SCRIPT_DIR="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"
elif [ "$ZSH_VERSION" ]; then
    SCRIPT_DIR="$(realpath "$(dirname "${(%):-%N}")")"
else
    SCRIPT_DIR="$(realpath "$(dirname "$0")")"
fi

# Build verusc
(cd "$SCRIPT_DIR/verusc" && cargo build --release) || return 1

REAL_CARGO="$(which cargo)"

function vargo {
    RUSTC_WRAPPER="$SCRIPT_DIR/verusc/target/release/verusc" "$REAL_CARGO" "$@"
}

function cargo {
    echo You have activated the build environment of Verus, so it is likely that
    echo you want to use \`vargo\` instead of \`cargo\`. Restart the shell to disable.
}
