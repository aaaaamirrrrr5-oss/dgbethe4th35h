# SiteGuard v0.6.0 — Domain Modules and Implementation Matrix

این نسخه ادامه افزایشی v0.5.1 است. UI اصلی Compose، رنگ‌های مشکی/قرمز، داشبورد و Bottom Navigation حفظ شده است.

| سند | ماژول/فایل | قابلیت قابل استفاده | وضعیت و مرز فعلی |
|---:|---|---|---|
| 11 | `GitHubToolIntelligence.kt` | ثبت metadata ابزار، بررسی قالب مخزن GitHub، pin کردن release/commit/hash، چک‌لیست مجوز/اسکریپت/وابستگی/شبکه، adapter contract، چرخه عمر و تأیید دستی | Partially Supported؛ discovery زنده، ذخیره دائمی registry، دانلود/نصب ابزار و sandbox واقعی انجام نمی‌شود. |
| 12 | `AttackGraphRiskEngine.kt` | node/edge versioned، evidence/provenance/timestamp/confidence/validity، تمایز observed/inferred، BFS مسیر کاندید، weakest-link confidence و risk score با contributionهای قابل توضیح | Partially Supported؛ graph از تمام دامنه‌ها به‌طور خودکار و پایدار ingest نمی‌شود؛ UI گراف تعاملی کامل ندارد؛ داشبورد تعداد node/edge را نمایش می‌دهد و گراف فعلی از یافته‌های نشست ساخته می‌شود؛ score داخلی جای CVSS نیست. |
| 13 | `RemediationPatchEngine.kt` | ساخت case، workflow تأیید، patch preview فقط برای snippet دقیق و یکتا، هش منبع، regression/staging/rollback record | Partially Supported؛ برنامه اصلاح از کارت یافته قابل بازبینی است؛ فایل اصلی یا production تغییر نمی‌کند؛ PR creation، backup واقعی و اجرای تست روی پروژه واردشده پیاده نیست. |
| 14 | `ThreatForensicsEngine.kt` | SHA-256 شواهد، chain-of-custody hash chain، timeline با UTC normalization، تطبیق دقیق indicator با متن و expiration/provenance | Partially Supported؛ feed زنده، parser جامع forensic، evidence vault پایدار، quarantine و تحلیل/اجرای malware وجود ندارد. |
| 15 | `SecurityAutomation.kt` | صف bounded، idempotency، cancellation، retry، scope revalidation هنگام claim، pause بعد از expiry، emergency-stop gate و drift fingerprint | Partially Supported؛ queue در حافظه فرایند است؛ WorkManager/durable recovery/notifications/always-on monitoring پیاده نیست. اجرای زمان‌بندی‌شده به حضور اپ/فراخوانی caller وابسته است. |
| 16 | `LabSimulation.kt` | کاتالوگ سناریوهای deterministic، fixtureهای synthetic، evidence، finding IDs و pass-after-fix؛ اجرای smoke از UI | Partially Supported؛ هیچ container/VM/OWASP target به‌طور خودکار نصب یا اجرا نمی‌شود؛ سناریوها شبیه‌سازی محلی پیکربندی‌اند، نه pentest lab کامل. |
| 17 | `ReportingQualityEngine.kt`, `MainActivity.kt` | گزارش HTML امن با escaping، coverage denominator، statusهای executed/skipped/blocked/failed، metricهای precision/recall/FPR از labeled fixtures و خروجی JSON قبلی | Partially Supported؛ PDF و دو قالب executive/technical مجزا اضافه نشده؛ معیارها فقط وقتی داده واقعی fixture وارد شود محاسبه می‌شوند. |
| 18 | `SecurityPolicyEngine.kt` | authorization object گسترده، exact domain/IP CIDR، exclusions، class/method allowlist، third-party gate، private-range check، global emergency stop و bounded audit trail | Partially Supported؛ ماژول policy مستقل وجود دارد؛ تمام adapterهای فعلی هنوز از یک policy object مشترک واحد تغذیه نمی‌شوند. |
| 19 | `ExtendedSpecificationTest.kt`, `ReportingQualityEngine.kt` | تست‌های unit برای lifecycle، graph، patch، forensics، automation، lab، policy، QA، report و release gate | Tested در harness محلی؛ اجرای رسمی Gradle/JUnit، پوشش Android API/ABI، precision/recall مجموعه واقعی و benchmark RAM/CPU/thermal هنوز انجام نشده. |
| 20 | `.github/workflows/android-ci.yml`, `tools/check-no-hosted-ai.sh` | CI برای JDK 17، Android SDK 35، Gradle 8.9، unit tests، lint، debug/release assemble، dependency report، checksum و امضای اختیاری از GitHub Secrets | Partially Supported؛ این محیط APK تولید نکرده؛ امضای release فقط با secrets کاربر؛ Gradle Wrapper و worker مستقل Linux داخل ZIP نیست. |
| 21 | `ExecutionOrderAcceptance.kt`, `SPEC_EXECUTION_LOG_v0.6.0.md` | ledger اسناد 00–21، کنترل ترتیب و gap، statusهای honest، acceptance gate و plan مرحله‌ای | Implemented در حد ledger/گزارش؛ Master Prompt همچنان دو مشخصه اجباری 22 و 23 را مطالبه می‌کند که هنوز دریافت نشده‌اند. |

## اتصال به رابط

- کارت «مرکز عملیات و هوشمندی دفاعی» با همان تم موجود به داشبورد افزوده شد.
- اجرای سناریوهای آزمایشگاهی فقط روی داده synthetic و به‌صورت محلی از همان کارت ممکن است.
- گزارش HTML از همان کارت قابل اشتراک است؛ خروجی JSON قبلی و bottom navigation حفظ شده‌اند.
- تمام بخش‌های جدید دارای وضعیت/محدودیت مستند هستند؛ هیچ شمارنده ساختگی برای ابزار نصب‌شده، job فعال، تهدید زنده یا پوشش امنیتی نمایش داده نمی‌شود.

## قابلیت‌هایی که عمداً اجرا نمی‌شوند

دانلود یا اجرای خودکار مخازن GitHub، exploit واقعی، credential theft، stealth/evasion، persistence، exfiltration، lateral movement، دستکاری production، پرداخت/سفارش WooCommerce، تغییر IAM یا cluster، اجرای malware و اتصال به سرویس AI/cloud inference وجود ندارد.
