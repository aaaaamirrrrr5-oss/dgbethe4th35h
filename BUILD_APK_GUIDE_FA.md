# راهنمای ساخت APK — SiteGuard Android v0.13.0

## روش پیشنهادی: GitHub Actions

1. ZIP را استخراج کنید.
2. کل پوشه `SiteGuard-Android-v0.13.0` را به یک repository جدید GitHub آپلود کنید (همه فایل‌های مخفی مثل `.github` و `.gitignore` را نیز حفظ کنید؛ پوشه `.git` را برای upload لازم نیست).
3. وارد تب **Actions** شوید.
4. workflow با نام **Android CI** را از فایل `.github/workflows/android-ci.yml` اجرا کنید.
5. بعد از سبز شدن تمام مراحل، وارد همان run شوید و artifact زیر را بگیرید:
   - `siteguard-android-artifacts`
6. داخل artifact، APK debug/release و فایل checksumهای APK را بررسی کنید.
7. قبل از نصب release، checksum و امضای APK را بررسی کنید.

## امضای نسخه Release

برای تولید signed release، Keystore خودتان را به‌صورت GitHub Actions Secrets ثبت کنید:

- `SITEGUARD_KEYSTORE_BASE64`
- `SITEGUARD_KEY_ALIAS`
- `SITEGUARD_KEYSTORE_PASSWORD`
- `SITEGUARD_KEY_PASSWORD`

Keystore/private key را داخل GitHub repository، ZIP یا source code قرار ندهید. در صورت تنظیم صحیح secrets، APK امضاشده همراه checksumها در همان artifact با نام `siteguard-android-artifacts` قرار می‌گیرد؛ فایل keystore و نسخه unsigned release پیش از upload حذف می‌شوند. بدون secrets، APK release به‌صورت unsigned ارائه خواهد شد و برای توزیع نهایی مناسب نیست.

## محیط دستی Android Studio

نیاز است: JDK 17، Android SDK Platform 35، Build Tools 35.0.0، Android Gradle Plugin 8.7.3 و Gradle 8.9.

```bash
gradle --no-daemon :app:testDebugUnitTest
gradle --no-daemon :app:lintDebug
gradle --no-daemon :app:assembleDebug
gradle --no-daemon :app:assembleRelease
```

این ZIP Gradle Wrapper کامل ندارد. Android Studio یا GitHub Actions باید Gradle را فراهم کند.

## نکات مهم

- نسخه فعلی: `0.13.0`، versionCode `14`، JSON report schema `7`.
- بررسی DNS از Google Public DNS-over-HTTPS استفاده می‌کند؛ نام دامنه‌ای که بررسی می‌کنید برای resolver عمومی قابل مشاهده است.
- صف زمان‌بندی محلی و رمزگذاری‌شده است؛ WorkManager کارهای سررسیدشده را در پس‌زمینه و با زمان‌بندی شناور سیستم پیگیری می‌کند. اجرای دقیق در دقیقه تعیین‌شده یا مانیتورینگ دائمی تضمین نمی‌شود؛ دکمه اجرای دستی foreground نیز وجود دارد.

- این ZIP سورس پروژه است، APK آماده نصب نیست.
- Build موفق در محیط GitHub هنوز باید واقعاً اجرا شود؛ وجود workflow به معنی build موفق نیست.
- `applicationId` تغییر نکرده و `versionCode` در این ارتقا از 13 به 14 افزایش یافته؛ با این حال upgrade واقعی روی گوشی باید تست شود.
- سورس v0.7.0 را تا تأیید نصب/upgrade و عملکرد نسخه جدید نگه دارید.
