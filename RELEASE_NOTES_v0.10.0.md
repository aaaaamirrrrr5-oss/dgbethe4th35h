# SiteGuard Android v0.10.0

## امنیت مجوز و Scope

- اعتبارسنجی path در `Authorization.kt` اکنون مسیرهای absolute و محدود را می‌پذیرد و کنترل‌کاراکترها، backslash، dot-segment، percent escape ناقص، encoded dot/slash/backslash/NUL/CR/LF و double-encoding `%25` را رد می‌کند.
- manifestهای نامعتبر به‌صورت fail-closed رد می‌شوند: شناسه/اظهار مالکیت خالی، زمان شروع/پایان نامعتبر، بازه منقضی یا معکوس، بودجه درخواست خارج از محدوده، port نامعتبر، host نامعتبر، method غیر از passive GET و فهرست‌های بیش‌ازحد بزرگ رد می‌شوند.
- تطبیق path بر اساس مرز segment انجام می‌شود؛ `/admin` مجوز `/administrator` ایجاد نمی‌کند. excluded path نیز روی زیرمسیرهای همان segment اعمال می‌شود.
- canonicalization میزبان شامل IDN و IPv4 سخت‌گیرانه است؛ شکل‌های مبهم مانند `127.1` و octetهای دارای leading zero رد می‌شوند.
- normalize URL طول ورودی، scheme، userinfo، fragment، port، whitespace/control و path را اعتبارسنجی می‌کند.

## پایداری اسکن و خزش

- `ScanEngine` دارای deadline coroutine برابر ۲۶ ثانیه شده است؛ cancellation جداگانه منتشر می‌شود و به‌عنوان خطای معمول شبکه/اسکن ثبت نمی‌شود.
- `WebsiteDiscoveryEngineV1` گزینه `maxDurationMs` با بازه ۵٬۰۰۰ تا ۱۸۰٬۰۰۰ میلی‌ثانیه دارد (پیش‌فرض ۶۰ ثانیه)، در loop و اطراف fetch نقاط بررسی cancellation دارد و لغو را به‌عنوان `REQUEST_FAILED` ثبت نمی‌کند.
- `MainActivity` پیام timeout را از لغو عادی جدا می‌کند.
- محدودیت فنی resolver سیستم باقی است: `InetAddress.getAllByName` ممکن است در لایه native blocking باشد؛ deadline تضمین interrupt فوری DNS در تمام دستگاه‌ها نیست.

## پاک‌سازی شواهد و گزارش

- redaction برای JSON key/value، assignmentهای quoted/unquoted، Authorization Bearer/Basic، PEM private key، توکن‌های GitHub، AWS access key، JWT و URL دارای username/password اضافه/تقویت شد.
- فیلدهای یافته، evidence و remediation plan قبل از خروجی JSON پاک‌سازی می‌شوند؛ از جمله root-cause hypothesis و proposed patch diff.
- نسخه برنامه و schema در `SiteGuardBuildInfo.kt` متمرکز شده‌اند: app `0.10.0`, versionCode `11`, JSON report schema `4`.

## آزمون و مستندات

- regression testهای JUnit برای scope و redaction اضافه شدند.
- release gate بررسی وجود تست‌ها، deadline/cancellation و scrub شدن patch report را انجام می‌دهد.
- ماتریس ۴۰ حوزه با delta نسخه ۰٫۱۰ تکمیل شد، بدون اینکه حوزه‌ای نادرست Complete/ Tested اعلام شود.

## رفتارهای حفظ‌شده

- تم مشکی/قرمز، داشبورد و چهار مقصد نوار پایین حفظ شده‌اند.
- پروژه همچنان local-first است و هیچ AI API، hosted inference یا backend اجباری اضافه نشده است.
- اسکن شبکه همچنان passive و محدود به مجوز میزبان/درگاه/مسیر است؛ redirect خودکار دنبال نمی‌شود.
- اصلاحات حساس فقط plan/preview هستند؛ هیچ تغییر خودکاری روی production، سفارش، پرداخت، مشتری یا موجودی انجام نمی‌شود.

## اعتبارسنجی و محدودیت‌ها

- Kotlin/JVM compilation برای policy، scan/crawler core با stubs محدود، و policy smoke testها اجرا می‌شوند و نتیجه دقیق در `TEST_RESULTS_v0.10.0.txt` ثبت شده است.
- این بررسی‌ها جایگزین Gradle/Android/Compose build یا اجرای JUnit در Gradle نیستند.
- APK، signing، install، lint، Android device, UI/RTL/TalkBack و lifecycle در این محیط اجرا نشده‌اند.
- ۴۰ حوزه همچنان: ۳۸ Partial، یک Unsupported، یک Blocked؛ تمام ۲٬۰۰۰ معیار پذیرش تکمیل نشده‌اند.
