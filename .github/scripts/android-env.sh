#!/usr/bin/env bash
# Configure Cargo to cross-compile for Android with the NDK preinstalled on GitHub runners.
# Usage: bash .github/scripts/android-env.sh <rust-target> [api-level]
set -euo pipefail

target="${1:?usage: android-env.sh <rust-target> [api-level]}"
api="${2:-24}" # Termux requires Android 7.0 (API 24) or newer

ndk="${ANDROID_NDK_LATEST_HOME:-${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}}"
if [[ -z "$ndk" || ! -d "$ndk" ]]; then
  echo "Android NDK not found (ANDROID_NDK_LATEST_HOME / ANDROID_NDK_HOME / ANDROID_NDK_ROOT)" >&2
  exit 1
fi
bin="$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin"

case "$target" in
  aarch64-linux-android)   clang_triple="aarch64-linux-android" ;;
  armv7-linux-androideabi) clang_triple="armv7a-linux-androideabi" ;;
  x86_64-linux-android)    clang_triple="x86_64-linux-android" ;;
  i686-linux-android)      clang_triple="i686-linux-android" ;;
  *) echo "unsupported Android target: $target" >&2; exit 1 ;;
esac

linker="$bin/${clang_triple}${api}-clang"
if [[ ! -x "$linker" ]]; then
  echo "linker not found: $linker" >&2
  exit 1
fi

upper="$(printf '%s' "$target" | tr 'a-z-' 'A-Z_')"
lower="${target//-/_}"
{
  echo "CARGO_TARGET_${upper}_LINKER=$linker"
  echo "CC_${lower}=$linker"
  echo "AR_${lower}=$bin/llvm-ar"
} >> "$GITHUB_ENV"
echo "$bin" >> "$GITHUB_PATH"
echo "NDK: $ndk"
echo "Linker: $linker"
