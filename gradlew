#!/bin/sh
# Bootstrap stub. The official Gradle wrapper JAR is a binary that could not be shipped in this source package.
# On first run this script generates the official gradlew/gradlew.bat/wrapper JAR (replacing this stub) and re-runs.
set -eu
APP_HOME="$(cd "$(dirname "$0")" && pwd -P)"
if [ ! -f "$APP_HOME/gradle/wrapper/gradle-wrapper.jar" ]; then
  echo "gradle-wrapper.jar not found: generating the official Gradle wrapper (one-time) ..." >&2
  bash "$APP_HOME/tools/bootstrap-wrapper.sh" >&2
  [ -f "$APP_HOME/gradle/wrapper/gradle-wrapper.jar" ] || { echo "Wrapper bootstrap failed." >&2; exit 1; }
fi
exec "$APP_HOME/gradlew" "$@"
