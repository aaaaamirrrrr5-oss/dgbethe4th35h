#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command -v kotlinc >/dev/null 2>&1 || { echo "kotlinc is required (Kotlin/JVM CLI)." >&2; exit 2; }
command -v java >/dev/null 2>&1 || { echo "Java is required." >&2; exit 2; }
OUT="${TMPDIR:-/tmp}/siteguard-v014-smoke"
mkdir -p "$OUT"
mapfile -t SOURCES < <(find "$ROOT/app/src/main/java/com/siteguard/app/advanced" -maxdepth 1 -name '*.kt' -print | sort)
kotlinc "$ROOT/app/src/main/java/com/siteguard/app/core/Authorization.kt" "$ROOT/app/src/main/java/com/siteguard/app/core/SiteGuardBuildInfo.kt" "$ROOT/app/src/main/java/com/siteguard/app/core/PinnedHttpsClientV1.kt" "${SOURCES[@]}" "$ROOT/tools/AdvancedModuleSmoke.kt" -include-runtime -d "$OUT/siteguard-advanced-smoke.jar"
java -jar "$OUT/siteguard-advanced-smoke.jar"
