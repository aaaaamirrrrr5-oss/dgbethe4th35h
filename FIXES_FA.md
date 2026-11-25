# اصلاحات انجام‌شده روی v0.14.0

1. **تزریق HTML در گزارش فنی:** آدرس صفحه‌های کشف‌شده از سایت هدف بدون escape در گزارش HTML قرار می‌گرفت. اکنون با `HtmlSecurityReportExporterV1.escapeHtml` escape می‌شود.
2. **HTML نامعتبر:** بخش‌های Discovery/Coverage/Forensic بعد از `</body></html>` اضافه می‌شدند؛ اکنون داخل `<body>` قرار می‌گیرند.
3. **کرش هنگام اشتراک گزارش بزرگ:** اشتراک JSON/HTML/SBOM با `EXTRA_TEXT` از سقف Binder (حدود ۱ مگابایت) عبور می‌کرد. کلاس جدید `SafeShare` متن‌های بزرگ را از طریق `FileProvider` (پوشه cache/shared) به‌صورت فایل می‌فرستد.
4. **Worker صف ارزیابی:** خواندن snapshot صف رمزگذاری‌شده به `Dispatchers.IO` منتقل شد.
5. **Worker به‌روزرسانی CISA:** لغو کوروتین اکنون همان `CancellationException` اصلی را دوباره پرتاب می‌کند.
6. **احتیاط سازگاری Kotlin 2.0.21:** `catch (_: ...)` به نام صریح تغییر کرد.

توجه: Gradle/Android SDK در محیط اصلاح موجود نبود؛ این تغییرات فقط با بازبینی ایستا، بررسی توازن نحوی، اعتبارسنجی XML و release gate مبدئی کنترل شده‌اند. اجرای CI/Gradle هنوز لازم است.
7. **تحلیل وب:** پیش از هر درخواست، دوباره resolve شدن میزبان به آدرس عمومی بررسی می‌شود (کاهش خطر DNS rebinding). pin کامل IP هنوز انجام نشده است.
8. تست واحد `HtmlReportEscapingTest` برای escape خروجی HTML اضافه شد.
9. ذخیره صف ارزیابی با `commit()` انجام می‌شود تا وضعیت وظیفه با kill شدن پردازش از بین نرود.

## دور دوم اصلاحات (بازبینی ایستا)

10. **OSV — خطای کاذب وقتی آسیب‌پذیری وجود ندارد:** OSV در حالت «بدون advisory» کلید `vulns` را کلاً حذف می‌کند (`{}`)؛ کد قبلی `Expected JSON array` پرتاب می‌کرد و پرکاربردترین نتیجه (پکیج سالم) به‌صورت خطا نشان داده می‌شد. اکنون به‌عنوان «بدون advisory» برمی‌گردد.
11. **تحلیل سطح وب — یافته‌های کاذب «هدر وجود ندارد»:** اگر بدنهٔ صفحهٔ `/` بزرگ‌تر از ۵۱۲KB بود، خواندن با exception قطع می‌شد، هدرها ذخیره نمی‌شدند و هر ۵ هدر امنیتی «غایب» گزارش می‌شد. اکنون هدرها پیش از بدنه ثبت می‌شوند، بدنهٔ بزرگ truncate می‌شود (نه خطا)، و اگر پاسخ ریشه اصلاً مشاهده نشده باشد، ادعای «غایب بودن هدر» داده نمی‌شود.
12. **کلاینت WordPress:** پیش از هر درخواست احرازشده، resolve مجدد و بررسی IP عمومی انجام می‌شود تا Application Password به IP خصوصی/رزروشده (DNS rebinding) ارسال نشود. (pin کامل socket هنوز انجام نشده؛ این اقدام فقط پنجرهٔ حمله را کوچک می‌کند.) پاسخ بزرگ‌تر از سقف نیز دیگر کل مسیر را شکست نمی‌دهد.
13. **کش CISA:** `catalogVersion/dateReleased/sha256/source` بدون escape در JSON کش نوشته می‌شد؛ اکنون همه quote/escape می‌شوند.
14. **Patch محلی:** فایل غیر UTF-8 (مثلاً Latin-1/باینری) بی‌صدا با U+FFFD بازنویسی و خراب می‌شد؛ اکنون patch رد می‌شود. بیت اجرایی فایل حفظ می‌شود و backup بلااستفاده در صورت شکست پاک می‌شود.
15. **ScanEngine:** وابستگی به smart-cast از `authorization?.x != y` حذف شد (null صریحاً رد می‌شود).
16. **فیلد Application Password:** از `KeyboardType.Password` استفاده می‌کند تا کیبورد رمز را پیشنهاد/یاد نگیرد.
17. تست‌های جدید: `RegressionFixesTest` (OSV بدون vulns، رد فایل غیر UTF-8، patch+rollback).

هنوز باز است (نیازمند اجرای واقعی): کامپایل Gradle/JUnit/lint، pin کردن SHA اکشن‌های GitHub، تأیید وجود نسخهٔ `work-runtime-ktx:2.12.0` و سازگاری آن با `compileSdk 35`، و pin کامل IP در کلاینت‌های WordPress/WebSurface.

## دور سوم
18. **Worker صف ارزیابی:** مهلت کلی اسکن (`TimeoutCancellationException`) زیرکلاس `CancellationException` است و worker آن را مثل «توقف OS» دوباره پرتاب می‌کرد؛ نتیجه: کل اجرای worker قطع می‌شد و taskهای سررسیدشدهٔ دیگر می‌ماندند. اکنون تایم‌اوت یک شکست عادی task است (ثبت + retry در سقف مجاز) و صف ادامه می‌یابد.
19. **انتخاب APK/AAB بزرگ:** خواندن تا ۱۲۰MB در حافظه می‌تواند `OutOfMemoryError` بدهد که با `catch (Exception)` گرفته نمی‌شد و برنامه کرش می‌کرد؛ اکنون پیام خطای قابل‌فهم نمایش داده می‌شود.

## دور چهارم
20. **تحلیل کد — خطوط بسیار بلند:** فایل‌های مینیفای‌شده/تولیدشده (یک خط چند صد کیلوبایتی) regexهایی مثل `[^;\n]*` را به زمان درجه‌دو می‌رساندند و اسکن می‌توانست کند یا قفل شود. اکنون تطبیق در پنجره‌های ۴۰۰۰ کاراکتری انجام می‌شود (تست: `LongLineAnalysisTest`).

## دور پنجم
21. **صف پایدار ارزیابی:** (الف) یک ردیف خراب دیگر کل صف را دور نمی‌ریزد و فقط همان ردیف حذف می‌شود؛ (ب) status ناشناخته دیگر بی‌صدا به `QUEUED` تبدیل نمی‌شود (می‌توانست taskِ لغوشده را زنده کند) و ردیف رد می‌شود (fail closed).
22. **تاریخچهٔ اسکن محلی:** سقف ۳MB برای مقدار رمزگذاری‌شده اضافه شد (قدیمی‌ترین ردیف‌ها حذف می‌شوند)، مشابه آرشیو ارزیابی‌ها.

## دور ششم
23. **سقف درخواست مجوز دور زده می‌شد:** `AuthorizationBudget` فقط در `ScanOrchestrator` مصرف می‌شد؛ taskهای صف (اجرای فوری و WorkManager) مستقیم `ScanEngine` را صدا می‌زدند و `maxRequests`/`requestsPerMinute` اعمال نمی‌شد. اکنون مصرف بودجه داخل `ScanEngine.scan` (تنها نقطهٔ عبور شبکه) انجام می‌شود و از Orchestrator حذف شد تا دوبار شمرده نشود. مانیفست taskهای زمان‌بندی‌شده `maxRequests=2` گرفت تا یک retry مجاز بماند.
24. **وابستگی:** `work-runtime-ktx` از `2.12.0` (تأییدنشده) به `2.10.0` (سازگار با `compileSdk 35`) برگشت؛ gate هم هماهنگ شد.
25. **CI:** اکشن‌ها روی major هایی که قطعاً وجود دارند (`checkout@v4`، `setup-java@v4`، `setup-android@v3`، `setup-gradle@v4`) قرار گرفتند. pin به SHA کامل هنوز لازم است (بدون شبکه نمی‌شود SHA را به‌دست آورد).

## دور هفتم (اصلاحات ساختاری)
26. **pin کامل IP در آداپتورها:** کلاس جدید `PinnedHttpsClientV1` (resolve فقط یک‌بار، بررسی همهٔ IPها با `AddressPolicy`، اتصال مستقیم به همان IP، SNI و بررسی hostname گواهی، **تکمیل handshake پیش از ارسال هر هدر/Application Password**، بدون redirect، سقف هدر/بدنه، پشتیبانی از chunked). `WordPressReadOnlyClientV1` و `WebSurfaceAnalyzerV1` به‌صورت پیش‌فرض از آن استفاده می‌کنند؛ پارامتر `connectionFactory` (برای تست) مسیر قدیمی را نگه می‌دارد. جلوی header/request-target injection (CR/LF) هم گرفته شد.
27. **بودجهٔ مجوز پایدار شد:** `AuthorizationBudget` حالا با `Store` (SharedPreferences؛ فقط id، شمارنده و زمان) ذخیره/بازیابی می‌شود و در `MainActivity` و worker وصل است؛ ری‌استارت پروسه دیگر بودجه را صفر نمی‌کند.
28. **تست‌های جدید:** `PinnedHttpsClientV1Test` (parse، chunked، truncate، 204/304، سرآیند بزرگ، رد IP خصوصی/ترکیبی، injection)، `AdapterTransportFixesTest` (بدنهٔ بزرگ، ریشهٔ ناموفق، پاسخ بزرگ WordPress) و `AuthorizationBudgetPersistenceTest`.
29. **Release gate:** چند invariant امنیتی (transport پین‌شده، مصرف بودجه فقط در `ScanEngine`، attach شدن store) به `final-release-gate.sh` اضافه شد؛ gate محلی اجرا و پاس شد (۲۳ PASS).

هنوز باز: کامپایل/JUnit واقعی، تست واقعی `PinnedHttpsClientV1` روی سرور TLS، pin کردن SHA اکشن‌های CI، Gradle wrapper jar، و انتقال ساخت صف از main thread.

## دور هشتم
30. **کار main thread در صف خودکار:** چهار دکمهٔ «زمان‌بندی»، «توقف اضطراری»، «اجرای کارهای سررسیدشده» و «بازنشانی توقف» مستقیماً `enqueue/emergencyStop/claimDue/resetEmergencyStop/snapshot` را روی رشتهٔ UI صدا می‌زدند؛ این توابع رمزگذاری Keystore و I/O فایل/SharedPreferences انجام می‌دهند و می‌توانستند UI را برای لحظاتی قفل کنند (یا در دستگاه‌های کند، ANR بدهند). اکنون این چهار مسیر در `scope.launch(Dispatchers.IO)` اجرا می‌شوند؛ ورودی‌های Compose (مثل `url`) پیش از ورود به coroutine در یک `val` محلی گرفته می‌شوند تا state از ترد پس‌زمینه خوانده نشود. لغو job و WorkManager (سبک) در دکمهٔ توقف اضطراری همچنان بی‌درنگ روی UI اجرا می‌شود.

## دربارهٔ «افزونه»
در این مخزن **هیچ افزونهٔ همراه (مثلاً پلاگین وردپرس) وجود ندارد** تا سخت‌شده شود؛ SiteGuard فقط یک اپ Android است. بخش WordPress آن (`WordPressReadOnlyClientV1`) صرفاً به‌صورت **فقط‌خواندنی** به REST API یک سایت وردپرسی که کاربر مالکش است متصل می‌شود (`wp/v2/users/me`, `settings`, `plugins`, `themes`, `wc/v3/system_status`) و هیچ کدی روی آن سایت نصب یا اجرا نمی‌کند؛ پس «غیرقابل هک کردنِ افزونه» در اینجا معنایی ندارد. اگر منظور شما افزونهٔ دیگری است که در این zip نبوده، لطفاً فایلش را هم بفرستید تا همان‌طور سخت‌سازی شود.

## دور هشتم (سخت‌سازی خود برنامه)
30. **Manifest/Android 12+:** `data_extraction_rules.xml` اضافه شد؛ هیچ داده‌ای از طریق backup ابری یا انتقال دستگاه‌به‌دستگاه خارج نمی‌شود.
31. **UI:** `FLAG_SECURE` (بدون اسکرین‌شات/thumbnail در recent apps برای یافته‌ها و فرم رمز) و `filterTouchesWhenObscured` (جلوگیری از tapjacking روی صفحه‌های رضایت و اعتبارنامه). توجه: خروجی PDF/JSON/اشتراک‌گذاری همچنان از داخل برنامه کار می‌کند.
32. **Release:** `isDebuggable = false` صریح و obfuscation بیشتر R8 (`-repackageclasses`, `-allowaccessmodification`)؛ gate این موارد را بررسی می‌کند.

### دربارهٔ «افزونه»
در این پروژه هیچ افزونه/extension (WordPress، مرورگر یا غیره) وجود ندارد؛ فقط خود برنامهٔ اندروید است (برنامه افزونه‌های WordPress سایت مقصد را فقط می‌خواند). «غیرقابل‌هک» برای هیچ نرم‌افزاری قابل تضمین نیست؛ آنچه ممکن است کاهش سطح حمله است و در دورهای ۱ تا ۳۲ انجام شد (pin شبکه، fail-closed، بودجهٔ مجوز، رمزنگاری Keystore، بدون backup، FLAG_SECURE، R8). اگر افزونه‌ای جداگانه دارید (مثلاً افزونهٔ WordPress یا Chrome) فایلش را بفرستید تا همین‌طور بازبینی و سخت‌سازی کنم.

## دور نهم (رفع خطای CI در GitHub)
33. **مرحلهٔ «Validate source and selected offline modules»:** `tools/run-advanced-smoke-tests.sh` با `kotlinc` فقط `Authorization.kt` و `advanced/*.kt` را کامپایل می‌کرد. تغییرات دورهای قبل دو چیز را شکسته بود: (الف) آداپتورها حالا به `core/PinnedHttpsClientV1.kt` و `core/SiteGuardBuildInfo.kt` وابسته‌اند؛ (ب) ذخیرهٔ بودجه در `Authorization.kt` از `org.json` استفاده می‌کرد که روی کلاس‌پث `kotlinc` خالی وجود ندارد. اکنون هر دو فایل به فهرست کامپایل اضافه شد و ذخیرهٔ بودجه با متن ساده (بدون org.json) نوشته شد.
34. بررسی ایستای کل کد: هیچ تعریف تکراری نوع در یک package، هیچ import گم‌شدهٔ کلاس‌های پلتفرم/JDK، و هیچ resource ارجاع‌شدهٔ ناموجود (manifest/theme/mipmap/xml) پیدا نشد. این بررسی‌ها جای کامپایلر را نمی‌گیرند.
