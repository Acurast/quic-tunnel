#!/bin/bash
set -e

# Android ARM64 (aarch64) build script
TARGET="aarch64-linux-android"
NDK="/Users/ale/Library/Android/sdk/ndk/29.0.13599879"

echo "Building for $TARGET..."
echo "Using NDK: $NDK"

# Set up environment
export ANDROID_NDK_HOME="$NDK"
export CC_aarch64_linux_android="${NDK}/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android24-clang"
export AR_aarch64_linux_android="${NDK}/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar"

# Build release
cargo build --release --target $TARGET --bin client

# Output location
echo ""
echo "Build complete!"
echo "Binary: target/${TARGET}/release/client"
ls -lh "target/${TARGET}/release/client" 2>/dev/null || echo "(run this script to generate)"

