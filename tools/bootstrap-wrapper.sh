#!/usr/bin/env bash
# Generates the official gradlew, gradlew.bat and gradle/wrapper/gradle-wrapper.jar (binary files that cannot be
# authored by hand). Works with or without a preinstalled Gradle: if `gradle` is not on PATH, the official
# Gradle 8.9 distribution is downloaded from services.gradle.org (checksum-verified) into the Gradle user home.
# Requires JDK 17+ and, for the download path, curl or wget plus unzip. Run once, then commit the generated files.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
GRADLE_VERSION="8.9"

command -v java >/dev/null || { echo "JDK 17+ is required (java not found on PATH)." >&2; exit 1; }

if command -v gradle >/dev/null; then
  GRADLE="gradle"
else
  command -v unzip >/dev/null || { echo "unzip is required to unpack the Gradle distribution." >&2; exit 1; }
  fetch() { # fetch URL DEST
    if command -v curl >/dev/null; then curl -fsSL --retry 3 -o "$2" "$1"
    elif command -v wget >/dev/null; then wget -q -O "$2" "$1"
    else echo "curl or wget is required to download Gradle." >&2; exit 1; fi
  }
  CACHE="${GRADLE_USER_HOME:-$HOME/.gradle}/siteguard-bootstrap"
  DIST="$CACHE/gradle-$GRADLE_VERSION"
  if [[ ! -x "$DIST/bin/gradle" ]]; then
    URL="https://services.gradle.org/distributions/gradle-$GRADLE_VERSION-bin.zip"
    TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
    echo "Downloading Gradle $GRADLE_VERSION from services.gradle.org ..."
    fetch "$URL" "$TMP/gradle.zip"
    fetch "$URL.sha256" "$TMP/gradle.zip.sha256"
    EXPECTED="$(tr -d '[:space:]' < "$TMP/gradle.zip.sha256")"
    ACTUAL="$(sha256sum "$TMP/gradle.zip" | cut -d' ' -f1)"
    [[ -n "$EXPECTED" && "$EXPECTED" == "$ACTUAL" ]] || { echo "Checksum mismatch for the Gradle download; aborting." >&2; exit 1; }
    mkdir -p "$CACHE"
    unzip -q "$TMP/gradle.zip" -d "$CACHE"
  fi
  GRADLE="$DIST/bin/gradle"
fi

"$GRADLE" wrapper --gradle-version "$GRADLE_VERSION" --distribution-type bin
[[ -f gradle/wrapper/gradle-wrapper.jar && -f gradlew ]] || { echo "Wrapper generation failed." >&2; exit 1; }
chmod +x gradlew
echo "Generated: gradlew, gradlew.bat, gradle/wrapper/gradle-wrapper.jar. Commit them, then verify with: ./gradlew --version"
