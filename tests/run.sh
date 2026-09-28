#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
build=$(mktemp -d)
trap 'rm -rf "$build"' EXIT
read -ra deps <<< "$(pkg-config --cflags --libs glib-2.0 gio-2.0 gusb openssl)"
flags=(-std=gnu99 -g -O1 -Wall -Wextra -Werror -Wno-unused-parameter -Itests/stubs -Isrc)
if [ "${SANITIZE:-1}" = 1 ]; then
  flags+=(-fsanitize=address,undefined -fno-omit-frame-pointer)
fi
for unit in tls image-program match pair; do
  extra=()
  case "$unit" in
    image-program) extra+=(src/s00a8-program-data.c);;
    pair) extra+=(src/s00a8-pair-data.c);;
  esac
  "${CC:-clang}" "${flags[@]}" "tests/test-$unit.c" "${extra[@]}" "${deps[@]}" -lm -o "$build/$unit"
  "$build/$unit"
done
python3 tests/test-capture-reference.py
python3 tests/test-identify-lifetime.py
