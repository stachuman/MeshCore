#!/usr/bin/env bash
# Host-side unit-test runner for RouteCache. No PlatformIO required.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

CXX="${CXX:-g++}"
CXXFLAGS="-std=c++17 -Wall -Wextra -Werror -O0 -g -DROUTECACHE_HOST_TEST=1"
INCLUDES="-I $REPO_ROOT/src"
SRCS="$SCRIPT_DIR/test_routecache.cpp $REPO_ROOT/src/helpers/RouteCache.cpp"
OUT="$SCRIPT_DIR/test_routecache_bin"

echo "[build] $CXX $CXXFLAGS"
$CXX $CXXFLAGS $INCLUDES $SRCS -o "$OUT"
echo "[run] $OUT"
"$OUT"
echo "[ok] all tests passed"
