# راهنمای ساخت SiteGuard Android 0.14.0

## ساخت روی Linux/macOS/WSL

نیازمندی‌ها: JDK 17، Android SDK، Android SDK Platform 35، Build Tools 35.0.0، Gradle 8.9 و دسترسی اینترنت برای دریافت dependencyها.

از ریشه پروژه:

```bash
gradle --version
./tools/run-advanced-smoke-tests.sh
./tools/build-release-v0.14.0.sh
```

در این سورس فایل‌های `gradlew` و `gradle-wrapper.jar` قرار نگرفته‌اند؛ بنابراین دستورها از Gradle نصب‌شده استفاده می‌کنند. در CI نیز Gradle 8.9 به‌صورت صریح provision می‌شود. اگر روی سیستم خود Gradle نصب دارید، برای تولید Wrapper معتبر اجرا کنید:

```bash
./tools/bootstrap-wrapper.sh
```

فایل‌های Wrapper تولیدشده را بعد از بررسی به مخزن اضافه کنید؛ هیچ فایل باینری جعلی یا ناقص به‌عنوان Wrapper در این بسته قرار داده نشده است.

## خروجی‌ها

- Debug APK: `app/build/outputs/apk/debug/app-debug.apk`
- Release APK: `app/build/outputs/apk/release/`
- Release AAB: `app/build/outputs/bundle/release/app-release.aab`
- R8 mapping: `app/build/outputs/mapping/release/mapping.txt`

## امضای Release

برای امضای APK و AAB، keystore خودتان را بسازید و چهار متغیر زیر را در محیط Gradle تنظیم کنید. فایل keystore و گذرواژه‌ها را داخل ZIP یا مخزن عمومی قرار ندهید.

```bash
export SITEGUARD_KEYSTORE_PATH="/absolute/path/release.jks"
export SITEGUARD_KEY_ALIAS="your-alias"
export SITEGUARD_KEYSTORE_PASSWORD="..."
export SITEGUARD_KEY_PASSWORD="..."
```

در GitHub Actions همین چهار مقدار باید به‌صورت Repository Secrets ذخیره شوند:

- `SITEGUARD_KEYSTORE_BASE64`
- `SITEGUARD_KEY_ALIAS`
- `SITEGUARD_KEYSTORE_PASSWORD`
- `SITEGUARD_KEY_PASSWORD`

بدون این secrets خروجی Release امضای نهایی ندارد و برای انتشار در Google Play آماده نیست.

## مراحل CI

Workflow با push، pull request یا `workflow_dispatch` اجرا می‌شود و به‌ترتیب preflight، smoke، JUnit، lint، APK و AAB را اجرا می‌کند. پس از اجرای موفق، Artifact با APK/AAB، mapping و SHA-256 در بخش Actions همان مخزن قرار می‌گیرد. تا زمانی که این workflow اجرا و موفق نشده، خروجی ساخت واقعی تأییدشده محسوب نمی‌شود.
