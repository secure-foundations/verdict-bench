#!/usr/bin/env bash

set -e

get_script_dir() {
    if [ -n "$BASH_VERSION" ]; then
        local script_path="${BASH_SOURCE[0]}"
    elif [ -n "$ZSH_VERSION" ]; then
        local script_path="${(%):-%N}"
    else
        local script_path="$0"
    fi
    realpath "$(dirname "$script_path")"
}

script_dir="$(get_script_dir)"

pushd "$script_dir/verusc" > /dev/null
"$(which cargo)" build --release
popd > /dev/null

# This "vargo" is not the same as Verus's internal vargo
vargo() {
    VERUS_FLAGS="$VERUS_FLAGS --no-lifetime" "$(which cargo)" "$@"
}

cargo() {
    echo You have activated the build environment of Verus, so it is likely that
    echo you want to use \`vargo\` instead of \`cargo\`. Restart the shell to disable.
}

export RUSTC_WRAPPER="$script_dir/verusc/target/release/verusc"

export -f vargo
export -f cargo

exec "$SHELL"
