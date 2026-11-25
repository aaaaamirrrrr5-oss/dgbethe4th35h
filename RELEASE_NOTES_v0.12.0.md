# SiteGuard Android v0.12.0

پایه: v0.11.0. نسخه برنامه `0.12.0`، versionCode `13`، schema گزارش JSON `6`.

## جدید

- **بررسی `security.txt` (RFC 9116):** یک GET روی HTTPS به `/.well-known/security.txt` بدون دنبال‌کردن redirect. یافته‌ها: `SG-SECTXT-MISSING` (فقط برای 404/410، اطلاعاتی)، `SG-SECTXT-NO-CONTACT`، `SG-SECTXT-NO-EXPIRES`، `SG-SECTXT-BAD-EXPIRES`، `SG-SECTXT-EXPIRED`. هیچ‌کدام CONFIRMED نیستند و این موارد آسیب‌پذیری نیستند، فقط شفافیت مسیر گزارش مسئولانه را می‌سنجند.
- **ارزیابی هدر HSTS موجود:** `SG-HSTS-INVALID`، `SG-HSTS-DISABLED` (max-age=0)، `SG-HSTS-SHORT` (< ۶ ماه) و `SG-HSTS-PRELOAD-INELIGIBLE`. نبود کامل هدر پیش‌تر توسط اسکن اصلی (`SG-TLS-001`) گزارش می‌شود و تکرار نشده است.
- بودجه hygiene اکنون حداکثر ۴ درخواست GET است (HTTP، robots.txt، sitemap، security.txt).
- JSON schema 6: بخش‌های `security_txt` و `hsts` به `passive_hygiene` اضافه شدند.
- تست JUnit جدید: `HygieneParsersTest`.

## محدودیت‌ها

- هیچ‌کدام از کد جدید در این محیط کامپایل یا با JUnit اجرا نشده است (کامپایلر Kotlin، Gradle و Android SDK در دسترس نبودند). فقط release gate و بررسی‌های ساختاری اجرا شد.
- امضای PGP، دسترس‌پذیری لینک‌های Contact/Policy و مسیر قدیمی `/security.txt` بررسی نمی‌شوند.
- HSTS فقط از اولین پاسخ HTTPS دیده‌شده خوانده می‌شود، نه از زیر دامنه‌ها یا preload list رسمی.
- همچنان باقی: enumeration نسخه/cipher، زنجیرهٔ میانی/OCSP/CT، رکوردهای DNS (SPF/DMARC/CAA)، اثبات مالکیت با DNS TXT، Gradle Wrapper و pin کردن actionها با SHA.
