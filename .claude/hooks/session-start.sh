#!/bin/bash
# SessionStart hook (仅 Claude Code on the web 远程容器):
# 安装与 .github/workflows/build.yml 对齐的构建工具链, 让会话内可直接
# 跑 go vet/test、Go/C/eBPF 交叉编译和 applabel dex 构建。
#   - third_party/libbpf 子模块
#   - Go 1.25 工具链 (由 go.mod 触发 GOTOOLCHAIN 自动下载)
#   - Android NDK r27c
#   - Android SDK: build-tools 34.0.0 + platforms android-34
# 幂等: 已安装的部分直接跳过。
set -euo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
ANDROID_ROOT=/opt/android
NDK_VER=r27c
NDK_DIR="$ANDROID_ROOT/android-ndk-$NDK_VER"
SDK_DIR="$ANDROID_ROOT/sdk"
CMDLINE_TOOLS_ZIP=commandlinetools-linux-11076708_latest.zip

log() { echo "[session-start] $*" >&2; }

# 1. libbpf 子模块 (hotspotd 构建需要)
if [ ! -f "$PROJECT_DIR/third_party/libbpf/src/libbpf.c" ]; then
  log "init submodules"
  git -C "$PROJECT_DIR" submodule update --init --recursive
fi

# 2. Go 工具链 + 模块
for d in daemon/hnc_httpd src/dpid; do
  (cd "$PROJECT_DIR/$d" && go version >/dev/null && go mod download)
done

# 3. Android NDK
mkdir -p "$ANDROID_ROOT"
if [ ! -x "$NDK_DIR/toolchains/llvm/prebuilt/linux-x86_64/bin/clang" ]; then
  log "install NDK $NDK_VER"
  tmp=$(mktemp -d)
  curl -fsSL -o "$tmp/ndk.zip" "https://dl.google.com/android/repository/android-ndk-$NDK_VER-linux.zip"
  unzip -q "$tmp/ndk.zip" -d "$ANDROID_ROOT"
  rm -rf "$tmp"
fi

# 4. Android SDK (cmdline-tools → build-tools + platform)
SDKMANAGER="$SDK_DIR/cmdline-tools/latest/bin/sdkmanager"
if [ ! -x "$SDKMANAGER" ]; then
  log "install Android cmdline-tools"
  tmp=$(mktemp -d)
  curl -fsSL -o "$tmp/c.zip" "https://dl.google.com/android/repository/$CMDLINE_TOOLS_ZIP"
  unzip -q "$tmp/c.zip" -d "$tmp"
  mkdir -p "$SDK_DIR/cmdline-tools"
  rm -rf "$SDK_DIR/cmdline-tools/latest"
  mv "$tmp/cmdline-tools" "$SDK_DIR/cmdline-tools/latest"
  rm -rf "$tmp"
fi
if [ ! -x "$SDK_DIR/build-tools/34.0.0/d8" ] || [ ! -f "$SDK_DIR/platforms/android-34/android.jar" ]; then
  log "install SDK packages"
  yes | "$SDKMANAGER" --sdk_root="$SDK_DIR" --licenses >/dev/null 2>&1 || true
  "$SDKMANAGER" --sdk_root="$SDK_DIR" "build-tools;34.0.0" "platforms;android-34" >/dev/null
fi
ln -sf "$SDK_DIR/build-tools/34.0.0/d8" /usr/local/bin/d8
ln -sf "$SDKMANAGER" /usr/local/bin/sdkmanager

# 5. 会话环境变量 (build.sh 们读 ANDROID_NDK / ANDROID_NDK_HOME)
if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
  cat >> "$CLAUDE_ENV_FILE" <<EOF
export ANDROID_HOME=$SDK_DIR
export ANDROID_SDK_ROOT=$SDK_DIR
export ANDROID_NDK=$NDK_DIR
export ANDROID_NDK_HOME=$NDK_DIR
EOF
fi

log "toolchain ready"
