# SiteGuard Android v0.14.0

نسخه فعلی پروژه `0.14.0` است (versionCode `15`، گزارش JSON schema `8`). این نسخه مرکز Advanced Security Hub و ماژول‌های مستقل برای تحلیل محلی شواهد، CISA KEV و OSV، بررسی فقط‌خواندنی WordPress/WooCommerce REST، تحلیل Passive وب/API، تقریب AST/Taint، بررسی ایستای Cloud/IaC، تحلیل محدود باینری APK، Patch محلی با hash guard و rollback، گزارش مقایسه‌ای رمزگذاری‌شده و زمان‌بندی به‌روزرسانی Threat Intelligence را اضافه می‌کند. جزئیات دقیق پوشش/محدودیت‌ها در `RELEASE_NOTES_v0.14.0.md`، `IMPLEMENTATION_MATRIX_v0.14.0.md` و `TEST_RESULTS_v0.14.0.md` آمده است.

**وضعیت اعتبارسنجی v0.14.0:** دوازده آزمون smoke مستقل JVM و ۱۵ متد تست جدید از طریق harness سازگار با API تست JUnit با موفقیت اجرا شده‌اند؛ source release gate نیز ۲۲ PASS و ۱ WARN داده است. اجرای رسمی Gradle/JUnit، Compose compile، lint، APK/AAB، signing و تست دستگاه هنوز تأیید نشده‌اند؛ GitHub Actions برای آن‌ها پیکربندی شده اما اجرا نشده است. این ZIP سورس کامل است، نه APK آماده نصب.

## افزوده‌های v0.14.0

- Advanced Security Hub با ده بخش داخلی و حفظ مسیرهای قبلی برنامه.
- تحلیل محلی rule/evidence-based؛ بدون API key و بدون ادعای LLM مولد.
- CISA KEV با cache و refresh روزانه WorkManager، به‌علاوه query به OSV.dev برای اکوسیستم‌های پشتیبانی‌شده.
- WordPress/WooCommerce Runtime فقط‌خواندنی و با رضایت صریح؛ تحلیل Passive وب/API و کنترل‌های امنیتی پاسخ.
- تحلیل lexical AST/Taint، تنظیمات IaC/Cloud، تحلیل bounded APK/DEX/AXML.
- Patch محلی قابل بازبینی با backup، hash precondition و rollback محافظت‌شده.
- Snapshot مقایسه‌ای رمزگذاری‌شده و خروجی Markdown/PDF فارسی.
- CI برای JUnit، lint، APK debug/release و AAB؛ امضای release فقط با Secrets تحت کنترل مالک پروژه.

**مرزهای مهم:** ماژول محلی یک LLM نیست؛ WP و وب فقط خواندنی/محدود هستند؛ AST/Taint، Cloud و APK تحلیل‌های محدودند؛ اصلاح remote/production وجود ندارد؛ نتیجهٔ واقعی Android build هنوز اثبات نشده است.

---

## افزوده‌های v0.13.0

- DNS posture: SPF، DMARC و CAA از Google Public DNS-over-HTTPS؛ نام دامنه برای query به resolver عمومی ارسال می‌شود.
- صف automation و گزارش‌ها با AES-GCM و Android Keystore؛ WorkManager برای اجرای زمان‌بندی‌شده پس‌زمینه و اجرای دستی foreground.
- asset drift baseline رمزگذاری‌شده و شاخص کیفیت شواهد مستقل از CVSS.
- خروجی PDF فارسی/RTL و تکمیل metadata نسخه در رابط کاربری.

---

## اصول ثابت

- بدون OpenAI/ChatGPT/Gemini/Claude API، API Key، hosted inference یا مدل ابری اجباری.
- بدون backend یا server اجباری؛ پردازش source archive، قوانین، evidence و گزارش به‌صورت محلی است.
- تحلیل rule-based و deterministic است؛ برنامه، LLM عمومی یا تضمین کشف همه آسیب‌پذیری‌ها نیست.
- درخواست شبکه فقط در محدوده دقیق مجوز، میزبان/درگاه/مسیر و بودجه ثبت‌شده اجرا می‌شود؛ redirect و دارایی کشف‌شده مجوز جدید ایجاد نمی‌کنند.
- پیش‌فرض read-only و غیرمخرب است. دسترسی به داده واقعی مشتری، پرداخت، سفارش، refund، inventory، email/SMS یا تغییر production در آزمون‌ها ممنوع است.
- وضعیت `PASS` فقط بعد از آزمون مستقیم و evidence صادر می‌شود. نبود finding معادل امن بودن نیست.

## ویژگی‌های قبلی حفظ شده‌اند

- داشبورد، ظاهر مشکی/قرمز، bottom navigation، انتخاب فایل با Android Storage Access Framework و خروجی JSON/HTML.
- اسکن passive HTTP/HTTPS یک درخواست محدود، کنترل hostname/port/path، DNS/IP pinning و بررسی response headers.
- تحلیل سورس PHP، JavaScript، TypeScript، Python، Java/Kotlin، C# و Go با قواعد موجود.
- تحلیل ZIP چندفایلی بدون استخراج روی دیسک، WordPress/WooCommerce source heuristics، dependency inventory، SBOM best-effort.
- دانش محلی SQLite/FTS، mobile/network/cloud configuration review، API OpenAPI JSON static review، evidence graph، risk prioritization، threat/forensics، local lab و CI.

## افزوده‌های نهایی v0.8.0

### سند 22 — Website Security Specialist v2.0
- مدل `WebsiteEngagementManifestV2` با مالک، مجوزدهنده، روش/مرجع مجوز، allowlist دقیق، excluded hosts/paths، ports، test classes، محیط، بودجه درخواست، concurrency، حساب‌های synthetic، timezone و emergency stop.
- Scope gate برای host دقیق، پورت، path، زمان، test class و request budget؛ redirect/subdomain/third-party کشف‌شده خودکار مجاز نمی‌شود.
- ماتریس 16 کنترل وب و وردپرس/WooCommerce با وضعیت‌های `PASS`, `FAIL`, `NOT_TESTED`, `NOT_APPLICABLE`, `UNSUPPORTED`, `NEEDS_MANUAL_REVIEW`.
- گزارش specialist شامل پلتفرم تشخیص‌داده‌شده، inventory کامپوننت، پوشش کنترل‌ها، اولویت یافته‌ها، محدودیت‌ها و نقشه معماری شواهددار.
- کشف passive محدود داخلی با GET، scope re-check، pin شدن IP resolve شده، TLS hostname validation، بدون دنبال‌کردن redirect/link خارجی و بدون ارسال credential/form. Query string اولیه و Set-Cookie نگهداری نمی‌شوند.
- تحلیل ایستای GraphQL SDL، SOAP WSDL با غیرفعال‌سازی DTD/XXE و OpenAPI YAML خط‌محور.
- زنجیره تحویل شواهد محلی append-only با hash chaining و تشخیص تغییر؛ بدون امضای سخت‌افزاری یا شاهد مستقل.
- رجیستری وضعیت ۲۴ سند ۰۰ تا ۲۳ در داشبورد و خروجی JSON/HTML؛ هر سند کامل فعلاً PARTIALLY_SUPPORTED است.
- یال‌های `Observed` و `Inferred` جدا هستند؛ dependency اعلام‌شده در manifest به معنی نصب/resolve/runtime بودن آن نیست.
- پوشش اسکن passive یک درخواست GET را از آزمون‌های authentication، CORS preflight، BOLA، checkout و runtime جدا می‌کند.

### سند 23 — Website Remediation Playbook v1.0
- 14 الگوی اصلاح برای IDOR/BOLA، SQLi، XSS، CSRF، CORS، Security Headers/CSP، Auth/Session/Reset، File Handling، SSRF، WordPress، WooCommerce، API Rate Limit، Secrets/Dependencies و Patch Acceptance.
- هر برنامه اصلاح شامل مهار فوری، راهکار دائمی framework-aware، regression tests، staging validation، backup/rollback، downtime risk، owner role و monitoring است.
- تولید Diff فقط از snippet دقیق و یکتای منبع؛ مسیر absolute/Windows/traversal رد می‌شود.
- Patchهای playbook الگو هستند، نه patch آماده برای هر سایت. هیچ تغییر خودکاری روی فایل، database یا production اعمال نمی‌شود.
- خروجی تیکت توسعه‌دهنده از plan قابل اشتراک است.

## وضعیت پوشش واقع‌گرایانه

این نسخه specialist source-review و scope/remediation workflow را تقویت می‌کند؛ اما اجرای موارد زیر همچنان نیازمند محیط/ابزار/مجوز جدا است و نباید به‌عنوان قابلیت تأییدشده معرفی شود:

- نصب زنده WordPress/WooCommerce، plugin activation state، users/roles، multisite، database permissions و payment sandbox inspection.
- DAST کامل API، GraphQL/SOAP، authenticated BOLA/BFLA، webhook replay runtime و business-logic tests.
- AST/data-flow/taint کامل؛ parserهای زبان‌محور و semantic analysis کامل نیستند.
- Cloud IAM/Entra/AD live، binary APK/AAB analysis و local Linux isolated worker.
- اجرای کامل Docker/VM lab، always-on monitoring و durable background job guarantees؛ خروجی PDF در v0.13.0 اضافه شده است.
- advisory matching زنده با CVE/NVD/OSV و امضای ناشر؛ snapshot محلی فعلی کامل/به‌روز فرض نمی‌شود.

## Build APK / AAB

پیش‌نیازها: JDK 17، Android SDK Platform 35، Build Tools 35.0.0، AGP 8.7.3 و Gradle 8.9. Gradle Wrapper کامل در این ZIP وجود ندارد. در Android Studio پوشه پروژه را باز کنید یا workflow GitHub Actions را اجرا کنید:

```bash
gradle :app:testDebugUnitTest
gradle :app:lintDebug
gradle :app:assembleDebug
gradle :app:assembleRelease
```

راهنمای فارسی: `BUILD_APK_GUIDE_FA.md`. نام artifactها `siteguard-android-artifacts` (نام artifact در workflow) است. این بسته سورس است، نه APK آماده نصب.

## وضعیت اعتبارسنجی تاریخی v0.8.0

موارد زیر گزارش نسخه قبلی هستند و تست تازه v0.9.0 محسوب نمی‌شوند.

## گزارش اعتبارسنجی تاریخی v0.8.0

- تمام ۴۰ فایل Kotlin در core با kotlinc محلی و Android/JSON compatibility stubs کامپایل شدند؛ ۱۰ تست متمرکز v0.8.0 در runner محلی پاس شدند.
- Release preflight منبع: Manifest XML، endpointهای شناخته‌شده AI، بسته‌بندی اسناد ۰۰–۲۳، حفظ نشانگرهای UI و وجود مستندات release بررسی شد.
- release gate نسخه ۰٫۸٫۰، ۹ کنترل source preflight را اجرا می‌کرد؛ این کنترل‌ها جایگزین Gradle/Android build یا آزمون دستگاه نیستند.
- ۱۰ تست focused در `ExtendedModulesV080Test.kt` برای GraphQL، WSDL، OpenAPI YAML، CIDR، custody ledger، crawler، WordPress redaction، query blocking و registry 00–23 در runner محلی اجرا و پاس شدند؛ اجرای Gradle JUnit در این محیط انجام نشده است.
- Android Gradle build، lint، assembleDebug/Release، نصب/upgrade و UI/device testing در این محیط تأیید نشده‌اند؛ GitHub Actions باید در مخزن شما اجرا شود.

## وضعیت اعتبارسنجی v0.9.0

- `tools/final-release-gate.sh`: یازده کنترل source preflight پاس شدند؛ نبود Gradle Wrapper/Gradle executable به‌عنوان یک هشدار ثبت شد.
- بررسی parser فایل `MainActivity.kt` با `kotlinc` بدون خطای نحوی انجام شد، اما به علت نبود Android/Compose و وابستگی‌های core، این تلاش build یا type-check معتبر برنامه محسوب نمی‌شود.
- Android Gradle build، Compose/SDK compile، Gradle JUnit، lint، assemble APK، signing و device test اجرا نشده‌اند. جزئیات در `TEST_RESULTS_v0.9.0.txt`.

## مستندات

- `docs/specifications/` — اسناد 00 تا 23 و README ترتیب اجرا.
- `DOMAIN_MODULES_v0.8.0.md` — نقشه تاریخی ماژول‌ها و وضعیت نسخه ۰٫۸٫۰.
- `IMPLEMENTATION_MATRIX_00_23.md` — وضعیت تک‌تک ۲۴ سند و شکاف‌های باقی‌مانده.
- `docs/PROMPT_40_DOMAIN_COVERAGE_v0.10.0.md` (و نسخه تاریخی v0.9.0) — نگاشت ۴۰ حوزه پرامت به کد، تست و محدودیت واقعی.
- `SPEC_EXECUTION_LOG_v0.10.0.md` و `SPEC_EXECUTION_LOG_v0.9.0.md` — ثبت اجرای پنج مرحله ارتقا بر اساس پرامت؛ `SPEC_EXECUTION_LOG_v0.8.0.md` تاریخچه اجرای قبلی 00 تا 23 است.
- `SPECIFICATION_GAPS.md` — unsupported/partial و blockers.
- `TEST_PLAN.md`, `TEST_RESULTS_v0.8.0.txt`, `TEST_RESULTS_v0.9.0.txt`, `FINAL_EXECUTION_RESULT.md` — QA و نتیجه تست.
- `THREAT_MODEL.md`, `SBOM_STATUS.md`, `THIRD_PARTY_NOTICES.md` — امنیت و زنجیره تأمین.


## تغییرات v0.9.0

خلاصه تغییرات UX و گزارش در `RELEASE_NOTES_v0.9.0.md` آمده است. وضعیت واقعی build و source gate در `TEST_RESULTS_v0.9.0.txt` ثبت می‌شود.


## وضعیت اعتبارسنجی v0.10.0

تست‌های مستقل Kotlin/JVM، policy smoke، source release gate و بررسی صحت ZIP در `TEST_RESULTS_v0.10.0.txt` گزارش شده‌اند. این‌ها معادل Gradle build، JUnit task، APK یا تست دستگاه نیستند.
