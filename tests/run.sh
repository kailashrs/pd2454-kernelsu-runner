#!/bin/sh
# Host-only checks. An optional raw module enables binder sanitizer tests.
set -eu
if [ "$#" -gt 1 ]; then
    echo "usage: $0 [unrelocated-self-data-module.ko]" >&2
    exit 2
fi
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
compiler=${CC:-clang}
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/pd2454-tests.XXXXXX")
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM
python3 "$repo_dir/tests/check_stage.py"
"$compiler" -O1 -g -fsanitize=address,undefined -Wall -Wextra     -I"$repo_dir/src/timer" "$repo_dir/tests/test_module_state.c" -o "$test_dir/module-state"
"$test_dir/module-state"
if [ "$#" -eq 1 ]; then
    "$compiler" -O1 -g -fsanitize=address,undefined -Wall -Wextra         "$repo_dir/src/ksupatch.c" -o "$test_dir/ksupatch"
    python3 "$repo_dir/tests/test_binder.py" "$1" "$test_dir/ksupatch"
fi
