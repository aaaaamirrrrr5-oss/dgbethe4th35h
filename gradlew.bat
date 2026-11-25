@echo off
rem Bootstrap stub: the official wrapper JAR is not included in this source package.
if not exist "%~dp0gradle\wrapper\gradle-wrapper.jar" (
  echo gradle-wrapper.jar is missing.
  echo Run tools\bootstrap-wrapper.sh once from Git Bash or WSL, or open this folder in Android Studio and sync.
  exit /b 1
)
echo Unexpected state: use the generated official gradlew.bat.
exit /b 1
