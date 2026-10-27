#!/usr/bin/env bash
set -euo pipefail

CC="${CC:-cc}"
SRC="main.c"
OUT="cmdbox"

"$CC" -std=c11 -Wall -Wextra -O2 -m64 -o "$OUT" "$SRC"

echo "built: $OUT"
