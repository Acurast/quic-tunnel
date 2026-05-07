#!/usr/bin/env bash
set -euo pipefail

# Build the tunnel-client-ffi cdylib (libtunnel_client_ffi.so) for Android ABIs and
# optionally copy the artifacts into the acurast-data-transmitter project.
#
# Env vars (all optional):
#   ANDROID_NDK_HOME  Path to the NDK to use. Auto-detected if unset.
#   ANDROID_HOME      Android SDK root (used to locate NDK if above unset).
#   NDK_API_LEVEL     API level for the clang tool (default: 24).
#   ANDROID_TARGETS   Space-separated rust targets. Default: both ABIs.
#   COPY_TO           Path to the Android project root. If set, copies .so
#                     into <COPY_TO>/common/tunnel/src/main/jniLibs/<abi>/
#   SKIP_BUILD=1      Skip cargo build; only run the copy step.

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

NDK_API_LEVEL="${NDK_API_LEVEL:-24}"
ANDROID_TARGETS="${ANDROID_TARGETS:-aarch64-linux-android armv7-linux-androideabi}"

detect_ndk() {
  if [[ -n "${ANDROID_NDK_HOME:-}" && -d "$ANDROID_NDK_HOME" ]]; then
    echo "$ANDROID_NDK_HOME"
    return
  fi
  local sdk="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
  if [[ ! -d "$sdk/ndk" ]]; then
    sdk="$HOME/Android/Sdk"
  fi
  if [[ -d "$sdk/ndk" ]]; then
    # Pick the highest-versioned NDK available.
    local latest
    latest=$(ls -1 "$sdk/ndk" | sort -V | tail -n 1)
    if [[ -n "$latest" ]]; then
      echo "$sdk/ndk/$latest"
      return
    fi
  fi
  echo ""
}

detect_host_tag() {
  local uname_s uname_m
  uname_s=$(uname -s)
  uname_m=$(uname -m)
  case "$uname_s" in
    Darwin) echo "darwin-x86_64" ;;  # NDK ships only darwin-x86_64; works on arm64 via rosetta
    Linux)
      case "$uname_m" in
        x86_64|amd64) echo "linux-x86_64" ;;
        aarch64|arm64) echo "linux-aarch64" ;;
        *) echo "linux-x86_64" ;;
      esac
      ;;
    *) echo "linux-x86_64" ;;
  esac
}

clang_prefix_for_target() {
  case "$1" in
    aarch64-linux-android)     echo "aarch64-linux-android" ;;
    armv7-linux-androideabi)   echo "armv7a-linux-androideabi" ;;
    x86_64-linux-android)      echo "x86_64-linux-android" ;;
    i686-linux-android)        echo "i686-linux-android" ;;
    *) echo ""; return 1 ;;
  esac
}

cargo_target_var_name() {
  # Translates target triple into the CARGO_TARGET_<triple>_LINKER env-var
  # stem that cargo reads at build time.
  echo "$1" | tr '[:lower:]-' '[:upper:]_'
}

abi_for_target() {
  case "$1" in
    aarch64-linux-android)     echo "arm64-v8a" ;;
    armv7-linux-androideabi)   echo "armeabi-v7a" ;;
    x86_64-linux-android)      echo "x86_64" ;;
    i686-linux-android)        echo "x86" ;;
    *) echo ""; return 1 ;;
  esac
}

if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
  NDK="$(detect_ndk)"
  if [[ -z "$NDK" ]]; then
    echo "ERROR: could not locate an Android NDK. Set ANDROID_NDK_HOME or install one via Android Studio." >&2
    exit 1
  fi
  HOST_TAG="$(detect_host_tag)"
  TOOLCHAIN_BIN="$NDK/toolchains/llvm/prebuilt/$HOST_TAG/bin"
  if [[ ! -d "$TOOLCHAIN_BIN" ]]; then
    echo "ERROR: NDK toolchain not found at $TOOLCHAIN_BIN" >&2
    exit 1
  fi

  echo "Using NDK:       $NDK"
  echo "Host tag:        $HOST_TAG"
  echo "API level:       $NDK_API_LEVEL"
  echo "Targets:         $ANDROID_TARGETS"
  echo

  export ANDROID_NDK_HOME="$NDK"
  export AR="$TOOLCHAIN_BIN/llvm-ar"

  # Make sure the rust targets are installed.
  for t in $ANDROID_TARGETS; do
    if ! rustup target list --installed 2>/dev/null | grep -qx "$t"; then
      echo "Installing rustup target $t"
      rustup target add "$t"
    fi
  done

  for t in $ANDROID_TARGETS; do
    prefix="$(clang_prefix_for_target "$t")"
    clang="$TOOLCHAIN_BIN/${prefix}${NDK_API_LEVEL}-clang"
    if [[ ! -x "$clang" ]]; then
      echo "ERROR: clang not found at $clang (wrong API level or NDK layout?)" >&2
      exit 1
    fi
    stem="$(cargo_target_var_name "$t")"
    export "CARGO_TARGET_${stem}_LINKER=$clang"
    export "CC_${t//-/_}=$clang"
    export "AR_${t//-/_}=$TOOLCHAIN_BIN/llvm-ar"

    echo "==> cargo build --release --target $t -p tunnel-client-ffi"
    cargo build --release --target "$t" -p tunnel-client-ffi
  done
fi

echo
echo "Artifacts:"
for t in $ANDROID_TARGETS; do
  out="target/$t/release/libtunnel_client_ffi.so"
  if [[ -f "$out" ]]; then
    echo "  $out ($(du -h "$out" | cut -f1))"
  else
    echo "  $out (missing)"
  fi
done

if [[ -n "${COPY_TO:-}" ]]; then
  echo
  echo "Copying to Android project: $COPY_TO"
  for t in $ANDROID_TARGETS; do
    abi="$(abi_for_target "$t")"
    src="target/$t/release/libtunnel_client_ffi.so"
    dst_dir="$COPY_TO/common/tunnel/src/main/jniLibs/$abi"
    if [[ ! -f "$src" ]]; then
      echo "  skip $abi (no artifact at $src)"
      continue
    fi
    mkdir -p "$dst_dir"
    cp -f "$src" "$dst_dir/libtunnel_client_ffi.so"
    echo "  $abi -> $dst_dir/libtunnel_client_ffi.so"
  done
fi

echo
echo "Done."
