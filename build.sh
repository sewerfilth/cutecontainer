#!/bin/bash
# cutecontainer build script — cross-platform, cross-architecture
#
# Usage:
#   ./build.sh                          # native build (auto-detect)
#   ./build.sh --target x86_64-linux    # cross-compile
#   ./build.sh --target libnx           # Nintendo Switch
#   ./build.sh --test                   # build + run tests
#   ./build.sh --release                # release build (default)
#   ./build.sh --debug                  # debug build
#   ./build.sh --clean
#   ./build.sh --list-targets
#
# Targets:
#   aarch64-darwin   macOS Apple Silicon
#   x86_64-darwin    macOS Intel
#   x86_64-linux     Linux x64 (AMD + Intel)
#   i686-linux       Linux x86 32-bit
#   aarch64-linux    Linux ARM64
#   libnx            Nintendo Switch

set -e
cd "$(dirname "$0")"

TOOLCHAINS="../shared/toolchains"
TARGET=""
BUILD_TYPE="Release"
ACTION="build"
JOBS="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"

# ── Parse args ───────────────────────────────────────────────────────

while [ $# -gt 0 ]; do
    case "$1" in
        --target|-t)    TARGET="$2"; shift 2 ;;
        --test)         ACTION="test"; shift ;;
        --release)      BUILD_TYPE="Release"; shift ;;
        --debug)        BUILD_TYPE="Debug"; shift ;;
        --clean)        rm -rf build; echo "cleaned."; exit 0 ;;
        --list-targets) ls "$TOOLCHAINS"/*.cmake 2>/dev/null | sed 's|.*/||;s|\.cmake||' | sort -u; exit 0 ;;
        --help|-h)
            sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
            exit 0 ;;
        *)  echo "unknown option: $1"; exit 1 ;;
    esac
done

# ── Configure ────────────────────────────────────────────────────────

if [ -n "$TARGET" ]; then
    CMAKE_FILE="$TOOLCHAINS/$TARGET.cmake"
    if [ ! -f "$CMAKE_FILE" ]; then
        echo "error: unknown target '$TARGET'"
        echo "available: $($0 --list-targets | tr '\n' ' ')"
        exit 1
    fi
    BUILDDIR="build/$TARGET"
    echo "target: $TARGET"
    TOOLCHAIN_ARG="-DCMAKE_TOOLCHAIN_FILE=$CMAKE_FILE"
else
    BUILDDIR="build/native"
    TOOLCHAIN_ARG=""
fi

echo "build type: $BUILD_TYPE"
echo "output: $BUILDDIR/"

mkdir -p "$BUILDDIR"

# ── CMake configure + build ──────────────────────────────────────────

cmake -S . -B "$BUILDDIR" \
    $TOOLCHAIN_ARG \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    2>&1

cmake --build "$BUILDDIR" -j "$JOBS" 2>&1

# ── Test ─────────────────────────────────────────────────────────────

if [ "$ACTION" = "test" ]; then
    echo
    echo "=== running tests ==="
    cd "$BUILDDIR"
    ctest --output-on-failure 2>&1 || true
    cd - >/dev/null
fi

echo
echo "done: $BUILDDIR/"
ls -lh "$BUILDDIR"/libcutecontainer.* "$BUILDDIR"/cutecontainer_cli 2>/dev/null || true
