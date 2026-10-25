#!/bin/bash
# Pinned local AAR build for mist-framework (Real-QUIC step 1).
# Pins verified by spike S2 (2026-10-25); do NOT float these values.
#   Go toolchain : /home/hatch/go1.26/go/bin/go (go1.26.0; the
#                  workspace tools/go binary is go1.24.0 and does NOT
#                  satisfy quic-go v0.64.1's go >= 1.26 requirement)
#   Android SDK  : $HOME/android-sdk (platform android-34,
#                  build-tools 34.0.0, NDK 25.1.8937393, JDK 17)
#   gomobile     : golang.org/x/mobile v0.0.0-20261011034528-197770444867
#                  (declared as a tool dependency in mobile/go.mod)
#   androidapi   : 21 (NDK 25 rejects the default 16)
# NOTE: shell default environments leave ANDROID_HOME/ANDROID_NDK_HOME
# empty even though the SDK exists; this script exports them explicitly.
# CI (.github/workflows/build.yml) is NOT pinned by this script and is
# tracked separately (it currently floats gomobile @latest and uses a
# different SDK/NDK/API level); do not assume CI matches this script.
set -euo pipefail
cd "$(dirname "$0")"

GO=/home/hatch/go1.26/go/bin/go
export PATH="/home/hatch/go1.26/go/bin:$HOME/go/bin:$PATH"
export ANDROID_HOME="$HOME/android-sdk"
export ANDROID_NDK_HOME="$HOME/android-sdk/ndk"

"$GO" version | grep -q "go1.26" || { echo "build-aar: Go toolchain is not go1.26: $($GO version)" >&2; exit 1; }
[ -d "$ANDROID_HOME" ] || { echo "build-aar: ANDROID_HOME missing: $ANDROID_HOME" >&2; exit 1; }
[ -d "$ANDROID_NDK_HOME" ] || { echo "build-aar: ANDROID_NDK_HOME missing: $ANDROID_NDK_HOME" >&2; exit 1; }
command -v gomobile >/dev/null || { echo "build-aar: gomobile not in PATH ($HOME/go/bin)" >&2; exit 1; }

gomobile bind -androidapi 21 -target=android/arm64 \
  -o mistframework.aar \
  github.com/cien121/mist-framework/mobile
echo "build-aar: wrote mistframework.aar"
