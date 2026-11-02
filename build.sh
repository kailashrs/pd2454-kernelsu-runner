#!/bin/sh
set -eu
cd "$(dirname "$0")"
: "${NDK:?Set NDK to Android NDK r29}"
case "$(uname -s)" in
 Darwin) host_tag=darwin-x86_64 ;;
 Linux) host_tag=linux-x86_64 ;;
 *) echo 'Unsupported NDK host' >&2; exit 1 ;;
esac
compiler="$NDK/toolchains/llvm/prebuilt/$host_tag/bin/aarch64-linux-android35-clang"
stripper="$NDK/toolchains/llvm/prebuilt/$host_tag/bin/llvm-strip"
[ -x "$compiler" ] || { echo "Compiler missing: $compiler" >&2; exit 1; }
python3 tests/check_stage.py
mkdir -p bin
"$compiler" -O2 -std=gnu11 -static -fno-stack-protector -fno-pic -no-pie \
 -Wall -Wextra -Isrc/timer src/timer/timer.c -o bin/ic98260 -pthread \
 -Wl,--gc-sections -Wl,-z,norelro
for helper in ksupatch insmodf; do
 "$compiler" -O2 -static -Wall -Wextra "src/$helper.c" -o "bin/$helper"
done
for binary in bin/ic98260 bin/ksupatch bin/insmodf; do
 "$stripper" "$binary"
 shasum -a 256 "$binary"
done
