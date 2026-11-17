#!/usr/bin/env bash
# Reproducible Android release build script for UwUvpn / VeloxVPN (arm64-v8a + armeabi-v7a, 16 KiB ELF)
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JNI_DIR="$ROOT_DIR/android/app/src/main/jniLibs"
WORK_DIR="${WORK_DIR:-$ROOT_DIR/third_party}"
XRAY_RUST_VERSION="0.10.0"
ANDROID_API_LEVEL="${ANDROID_API_LEVEL:-24}"

: "${ANDROID_HOME:?Set ANDROID_HOME to your Android SDK path}"
export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$ANDROID_HOME}"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/27.2.12479018}"

if ! command -v cargo-ndk >/dev/null 2>&1; then
  echo "Installing cargo-ndk..."
  cargo install cargo-ndk --locked
fi

mkdir -p "$WORK_DIR" "$JNI_DIR/arm64-v8a" "$JNI_DIR/armeabi-v7a"

# 1. Fetch & patch xray-rust v0.10.0 (MPL-2.0) with REALITY X.509 v1 SPKI CertificateVerify fix
XRAY_SRC="$WORK_DIR/xray-rust-$XRAY_RUST_VERSION"
if [ ! -d "$XRAY_SRC" ]; then
  echo "Downloading aimalygin/xray-rust v$XRAY_RUST_VERSION..."
  curl -sSL "https://github.com/aimalygin/xray-rust/releases/download/v${XRAY_RUST_VERSION}/xray-rust-${XRAY_RUST_VERSION}.tar.gz" \
    | tar -xz -C "$WORK_DIR"
  patch -d "$XRAY_SRC" -p1 < "$ROOT_DIR/patches/xray-rust-0.10.0-reality-x509v1.patch"
fi

STRIP="$(find "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt" -name llvm-strip | head -n 1)"
PAGE_FLAGS="-C link-arg=-Wl,-z,max-page-size=16384 -C link-arg=-Wl,-z,common-page-size=16384"

echo "=== [1/3] Building libxray_ffi.so (arm64-v8a + armeabi-v7a) ==="
(
  cd "$XRAY_SRC"
  rustup target add aarch64-linux-android armv7-linux-androideabi
  CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS="$PAGE_FLAGS" \
  CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_RUSTFLAGS="$PAGE_FLAGS" \
  cargo ndk --platform "$ANDROID_API_LEVEL" -t arm64-v8a -t armeabi-v7a -o "$JNI_DIR" \
    build --locked -p xray-ffi --release
)
rm -f "$JNI_DIR"/arm64-v8a/libgotatun.so "$JNI_DIR"/armeabi-v7a/libgotatun.so
"$STRIP" --strip-unneeded "$JNI_DIR/arm64-v8a/libxray_ffi.so" "$JNI_DIR/armeabi-v7a/libxray_ffi.so"

echo "=== [2/3] Building libvelox_engine.so (arm64-v8a + armeabi-v7a) ==="
(
  cd "$ROOT_DIR/rust-engine"
  rustup target add aarch64-linux-android armv7-linux-androideabi
  CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS="$PAGE_FLAGS" \
  CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_RUSTFLAGS="$PAGE_FLAGS" \
  cargo ndk --platform "$ANDROID_API_LEVEL" -t arm64-v8a -t armeabi-v7a -o "$JNI_DIR" \
    build --lib --release
)
"$STRIP" --strip-unneeded "$JNI_DIR/arm64-v8a/libvelox_engine.so" "$JNI_DIR/armeabi-v7a/libvelox_engine.so"

echo "=== [3/3] Assembling Android release APK (R8 + resource shrinking) ==="
(
  cd "$ROOT_DIR/android"
  if [ -x ./gradlew ]; then
    ./gradlew :app:assembleRelease --no-daemon
  else
    gradle :app:assembleRelease --no-daemon
  fi
)

echo "Done! APK output:"
find "$ROOT_DIR/android" "${VELOX_BUILD_DIR:-$ROOT_DIR/android}" -name "app-release.apk" 2>/dev/null | sort -u
