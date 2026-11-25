# SiteGuard Android v0.10.0 — ثبت اجرای پنج مرحله

## Stage 1/5 — ممیزی و استخراج قرارداد

- نسخه واقعی پایه: `SiteGuard-Android-v0.9.0`؛ فایل‌ها و ماژول‌های موجود قبل از تغییر بررسی شدند.
- تغییرات در لایه core و گزارش‌دهی انجام شد؛ داشبورد و تم نسخه ۰٫۹ حفظ شدند.
- نقاط ریسک مورد هدف: اعتبارسنجی URL و authorization manifest، redaction شواهد، لغو و deadline عملیات شبکه، و صحت فراداده release.
- ماتریس کامل ۴۰ حوزه و حدود پذیرش حفظ شده؛ هیچ claim از تکمیل تمام ۲٬۰۰۰ معیار صادر نشده است.

## Stage 2/5 — طراحی و پیاده‌سازی

- `Authorization.kt`: path/host/port/time/budget canonicalization و fail-closed validation سخت‌گیرانه‌تر شد.
- `EvidenceSanitizer.kt`: پوشش credentialهای JSON، header، provider token، PEM، JWT و URL credential گسترش یافت.
- `PlatformContracts.kt`: فیلدهای remediation و متن‌های حساس گزارش نیز sanitize می‌شوند.
- `ScanEngine.kt` و `WebsiteDiscoveryEngineV1.kt`: timeout/deadline و cancellation propagation افزوده شد؛ cancellation خطای معمول درخواست محسوب نمی‌شود.
- `MainActivity.kt`: پیام timeout مجزا شد.
- `SiteGuardBuildInfo.kt`: metadata مرکزی نسخه/schema اضافه شد؛ app نسخه `0.10.0`, versionCode `11`, schema `4`.
- JUnit regression source برای scope و evidence redaction اضافه شد.

## Stage 3/5 — اتصال و یکپارچه‌سازی

- release gate بررسی می‌کند metadata نسخه، تست‌های جدید، scope hardening، redaction در patch report و deadline/cancellation وجود داشته باشند.
- گزارش JSON از metadata مرکزی نسخه/schema استفاده می‌کند.
- theme مشکی/قرمز، چهار destination موجود، سیاست بدون AI API، حالت local-first و preview-only remediation حفظ شدند.

## Stage 4/5 — اعتبارسنجی

- بررسی Kotlin/JVM برای `Authorization.kt`, `EvidenceSanitizer.kt`, `SiteGuardBuildInfo.kt` با kotlinc اجرا شد.
- policy smoke testها برای path، URL، host canonicalization، validity، port/budget و redaction اجرا شدند.
- مجموعه scan/crawler core با coroutine library و stubs محدود APIهای Android/Compose/manifest کامپایل شد؛ این تست فقط syntax/type checking بخش مورد نظر است، نه Android build.
- `bash -n` برای shell scriptها، parser XML برای AndroidManifest و source release gate اجرا شد.
- Gradle/JUnit/Android SDK/Compose/Lint/APK/device tests در این محیط اجرا نشدند؛ Gradle/SDK/Wrapper موجود نیستند.

## Stage 5/5 — تحویل

- نسخه تحویلی: `SiteGuard-Android-v0.10.0.zip`.
- گزارش آزمون: `TEST_RESULTS_v0.10.0.txt`.
- coverage delta: `docs/PROMPT_40_DOMAIN_COVERAGE_v0.10.0.md`.
- ریسک باقیمانده: native DNS resolver blocking، تست Gradle و Android build/device، و قابلیت‌های Partial/Unsupported در ماتریس ۴۰ حوزه.
- وضعیت نهایی: ارتقای سورس انجام شده؛ APK آماده نصب یا اجرای کامل تمام پرامت ادعا نمی‌شود.
