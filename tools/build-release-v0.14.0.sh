#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
command -v gradle >/dev/null 2>&1 || { echo "Gradle 8.9 is required; this project does not include gradlew/gradle-wrapper.jar." >&2; exit 2; }
gradle --version | grep -qE '^Gradle 8\.9([[:space:]]|$)' || { echo "This build is configured for Gradle 8.9." >&2; exit 2; }
command -v java >/dev/null 2>&1 || { echo "JDK 17 is required." >&2; exit 2; }
java -version 2>&1 | grep -Eq 'version "17([.]|\")' || { echo "Use JDK 17 for the release build." >&2; exit 2; }
if [[ -z "${ANDROID_HOME:-}" && -z "${ANDROID_SDK_ROOT:-}" ]]; then
  echo "ANDROID_HOME or ANDROID_SDK_ROOT must point to an installed Android SDK." >&2
  exit 2
fi
gradle --no-daemon :app:testDebugUnitTest :app:lintDebug :app:lintRelease :app:assembleDebug :app:assembleRelease :app:bundleRelease
test -s app/build/outputs/apk/debug/app-debug.apk
test -s app/build/outputs/bundle/release/app-release.aab
find app/build/outputs/apk app/build/outputs/bundle -type f \( -name '*.apk' -o -name '*.aab' \) -print0 | sort -z | xargs -0 sha256sum > siteguard-artifact-sha256.txt
printf '\nBuild completed. APK/AAB and checksum list:\n'
cat siteguard-artifact-sha256.txt
