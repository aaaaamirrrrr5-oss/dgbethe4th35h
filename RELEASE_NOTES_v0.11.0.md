# SiteGuard Android v0.11.0

پایه: سورس v0.10.0 (شامل گام‌های ۲ تا ۹ همان خط کار). نسخه برنامه `0.11.0`، versionCode `12`، schema گزارش JSON `5`.

## جدید

- **مشاهدهٔ نشست TLS پس از handshake موفق** (`TlsSessionInfoV1`): پروتکل و cipher مذاکره‌شده، موضوع/صادرکننده، بازهٔ اعتبار، الگوریتم امضا، نوع و طول کلید، تعداد SAN از نوع DNS و طول زنجیرهٔ ارائه‌شده. این داده در `fetchPinned` بعد از `startHandshake()` خوانده می‌شود.
- **ارزیابی نشست TLS** (`TlsSessionEvaluatorV1`): یافته‌های `SG-TLS-LEGACY-PROTOCOL`، `SG-TLS-WEAK-CIPHER`، `SG-TLS-WEAK-KEY`، `SG-TLS-WEAK-SIGNATURE`، `SG-TLS-CERT-EXPIRING` (≤ ۳۰ روز) و `SG-TLS-OBSERVED` (اطلاعاتی). هیچ‌کدام `CONFIRMED` نیستند، چون فقط یک نشست از همین دستگاه دیده شده است.
- **گزارش JSON schema 5:** بخش `passive_hygiene` شامل وضعیت اثبات مالکیت، robots/sitemap، رویدادها، محدودیت‌ها و `tls_session`. فقط وقتی export می‌شود که هدف گزارش با میزبان بررسی hygiene یکی باشد؛ در غیر این صورت `null` است تا داده‌ی میزبان دیگر وارد گزارش نشود.
- پنل مالکیت/hygiene خلاصهٔ TLS را نشان می‌دهد و گزارش کامل را به `MainActivity` می‌دهد.

## حفظ‌شده

- رفتار passive-only، pinning DNS، عدم دنبال‌کردن redirect، تم تیره/قرمز و local-first بدون AI API یا backend.

## محدودیت‌ها (صادقانه)

- هیچ‌کدام از کد جدید در این محیط کامپایل یا با JUnit اجرا نشده است: کامپایلر Kotlin، Gradle و Android SDK در دسترس نبودند. فقط بررسی‌های متنی/ساختاری و release gate اجرا شد.
- **Enumeration نسخه‌ها و cipherهای پشتیبانی‌شده انجام نمی‌شود.** فقط پارامترهای یک handshake دیده می‌شود؛ سرور ممکن است نسخه‌ها یا cipherهای ضعیف‌تری هم بپذیرد که این دستگاه هرگز مذاکره نمی‌کند.
- زنجیرهٔ میانی، OCSP و Certificate Transparency بررسی نمی‌شوند.
- رکوردهای DNS (SPF/DMARC/CAA) و اثبات مالکیت با DNS TXT هنوز پیاده‌سازی نشده‌اند (نیازمند DoH یا کتابخانهٔ resolver).
- Gradle Wrapper (`gradlew` و jar) هنوز در بسته نیست؛ `tools/bootstrap-wrapper.sh` را اجرا و خروجی را commit کنید.
- pin کردن actionهای GitHub با SHA هنوز TODO است.
