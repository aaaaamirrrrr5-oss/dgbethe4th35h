# SiteGuard v0.5.1 — Domain Module Integration

## هدف و اصول

نسخه 0.5.1 به‌صورت افزایشی روی 0.4.0 ساخته شده است. Compose dashboard، رنگ‌بندی تیره مشکی/قرمز، navigation پایین صفحه، اسکن قبلی وب، تحلیل تک‌فایل، ZIP، WordPress/WooCommerce، dependency inventory، SBOM و تاریخچه وب حفظ شده‌اند. ماژول‌های جدید در همان صفحه و همان الگوی بصری نمایش داده می‌شوند.

هیچ OpenAI/ChatGPT/Claude/Gemini API، API key، inference ابری، backend یا سرور اجباری اضافه نشده است. قابلیت‌های افزوده‌شده deterministic و source/configuration-based هستند؛ این قابلیت‌ها به‌عنوان هوش مصنوعی مولد معرفی نمی‌شوند.

## ماژول‌های جدید

### 1. Android/Mobile source review

- AndroidManifest متنی/decoded: `debuggable`, `usesCleartextTraffic`, componentهای exported، intent-filter و exported صریح برای target SDK 31+.
- مجوزهای حساس برای بازبینی اصل کمینه‌سازی داده.
- Network Security Config: cleartext permission و trust به CA کاربر.
- Java/Kotlin/WebView patterns: `addJavascriptInterface`, JavaScript, file access و الگوهای قدیمی world-readable preferences.
- Gradle build config review.
- تمام یافته‌ها در سطح heuristic/probable یا informational گزارش می‌شوند؛ APK binary AXML، runtime storage، Keystore behavior، TLS runtime، deep-link behavior و SDK provenance در این نسخه بررسی کامل نمی‌شوند.
- MobSF به‌صورت native داخل Android تعبیه نشده است؛ پیش‌نیاز/مجوز/سکوی آن باید برای worker محلی جداگانه ارزیابی شود.

### 2. Network/Enterprise configuration review

- SSH: `PermitRootLogin`, `PasswordAuthentication`, `PermitEmptyPasswords`.
- TLS server configuration: الگوهای پروتکل قدیمی.
- DNS zone config: انتقال zone به any.
- Nginx/Apache directory listing و server banner.
- Identity configuration exports: الگوهای MFA خاموش و OAuth redirect wildcard؛ خروجی JSON/Terraform/YAML فقط ایستا خوانده می‌شود.
- در UI یک TCP connect probe اضافه شده که فقط به IP عددی و پورت‌های صریح (حداکثر 16 پورت در هر نوبت) متصل می‌شود؛ DNS lookup، رنج‌اسکن، payload، banner grabbing و exploit ندارد. برای IPهای خصوصی باید مجوز شبکه داخلی نیز فعال باشد.
- سرویس صرفاً به‌صورت «احتمالی بر اساس شماره پورت» نمایش داده می‌شود؛ نسخه سرویس fingerprint نمی‌شود.
- TLS certificate probe برای پورت‌های 443/8443 فقط با trust store سیستم و hostname/IP validation عادی اجرا می‌شود؛ گواهی نامعتبر به‌عنوان معتبر پذیرفته نمی‌شود. برای سرویس‌هایی که certificate آن‌ها domain SAN دارد، ارائه نام TLS دقیقِ مجاز لازم است (در صورت نبود نام، IP SAN بررسی می‌شود).
- Active Directory/Entra ID، firewall effective rules، live segmentation، DNS query inventory و service/version fingerprinting کامل هنوز پشتیبانی نشده‌اند.

### 3. Cloud/Identity/Container/CI configuration review

- Dockerfile: اجرای root، tag شناور `latest` و `ADD` remote.
- Kubernetes YAML: privileged، host network/PID/IPC، hostPath، UID صفر و writable root filesystem.
- Terraform/IaC: IAM wildcard action/resource و ingress عمومی `0.0.0.0/0`.
- CI/CD workflow: الگوی حساس `pull_request_target`, secret context و action tag به‌جای commit SHA.
- secret-like assignment با redaction مقدار خام.
- این موتور هیچ حساب AWS/Azure/GCP یا cluster واقعی را متصل نمی‌کند؛ فقط فایل‌های ارائه‌شده را بازبینی می‌کند. دسترسی effective، policy inheritance، image registry CVE، provenance و runtime posture بررسی نمی‌شود.

### 4. Defensive Red-Team / Purple-Team Intelligence

- کاتالوگ دفاعی آغازین با MITRE ATT&CK mapping، پیش‌نیاز، defensive indicators، طرح شبیه‌سازی benign، telemetry، منطق detection، mitigation و validation.
- نمونه‌ها: T1190, T1078, T1552, T1059, T1610, T1098.
- تمرین‌ها synthetic و lab-oriented هستند؛ هیچ credential theft، persistence، evasion، exfiltration، malware، lateral movement یا exploit اجرا نمی‌شود.
- رابطه‌های graph تنها از `affectedAsset` دقیق و یافته مشاهده‌شده ساخته می‌شوند؛ مسیر حمله یا privilege path بدون evidence ساخته نمی‌شود.
- catalog فعلی عمدتاً L3 دفاعی است؛ L4 تنها در lab disposable قابل طراحی است و L5 داده/تحلیل حساس را وارد نمی‌کند.

### 5. Web/API schema review

- فایل‌های OpenAPI/Swagger JSON داخل ZIP با `ApiSchemaAnalyzer` بررسی می‌شوند.
- عملیات فاقد security مؤثر (در سطح operation و global) به‌صورت Probable و نیازمند بازبینی گزارش می‌شود؛ endpointهای عمومی ممکن است طراحی عمدی باشند.
- آدرس server از نوع `http://` به‌عنوان سرنخ تنظیمی گزارش می‌شود.
- تست زنده endpoint، auth/session، object/function authorization، tenant isolation، rate limit، business logic، GraphQL و SOAP در این ماژول اجرا نمی‌شود.

### 6. Universal assessment workflow

- enumهای domain/mode/state و safe test catalog اضافه شده‌اند.
- lifecycle، plan generation، statusهای PROPOSED/EXECUTED/SKIPPED/BLOCKED/FAILED، coverage denominator و emergency-stop primitive در هسته تعریف شده‌اند.
- plan به معنی اجرای واقعی نیست؛ تا زمانی که adapter و مانیفست دقیق هدف موجود نباشد، تست شبکه blocked/proposed می‌ماند.

### 7. Knowledge pack

- metadata منابع عمومی MITRE, CWE, NVD, CISA KEV, GitHub Advisories, OWASP, Android و WordPress به‌صورت محلی نگهداری می‌شود.
- رکوردهای CWE curated و فراداده ناشر/منبع به‌صورت پایدار در SQLite ذخیره می‌شوند؛ جدول FTS4 و بخش جست‌وجوی درون‌برنامه‌ای برای جست‌وجوی آفلاین وجود دارد.
- حالت pack صریحاً `offline-curated-reference` و `is_live_feed=false` است؛ metadata ناشر به معنی دریافت یا بازبینی تازه advisory نیست.
- SHA-256 هش رکورد canonical محلی است، نه امضای ناشر/اثبات اصالت publisher. feed واقعی، bundle امضاشده، key pinning، migrationهای نسخه بعد و rollback هنوز پیاده‌سازی نشده‌اند.

## قرارداد گزارش و سطح اطمینان

- یافته‌ها همچنان statusهای Confirmed/Probable/Unverified/Informational/False Positive را حفظ می‌کنند.
- rule-based evidence و limitations در JSON قرار می‌گیرند.
- `domain_coverage` هر ماژول را با state، تعداد فایل و یافته گزارش می‌کند.
- `defensive_attack_techniques` حاوی profileهای دفاعی مرتبط است.
- `evidence_graph` فقط رابطه‌های مستقیم مشاهده‌شده را نشان می‌دهد.
- نبود finding به معنی امنیت کامل یا پوشش کامل نیست.

## محدودیت‌های مهم باقی‌مانده

- Android Gradle build/APK و رفتار UI روی دستگاه باید در Android Studio/GitHub Actions تأیید شود.
- parserهای AST/data-flow/taint کامل و CVE/OSV matching تازه وجود ندارد.
- موبایل binary APK/MobSF runtime و تست واقعی emulator/device کامل نیست.
- WordPress/WooCommerce live runtime، role/capability، customer/order/payment operations و database inspection کامل نیست.
- API REST/GraphQL/SOAP DAST و business logic testing کامل نیست.
- cloud provider read-only adapters، AD/Entra live review، Kubernetes API و effective IAM graph کامل نیستند.
- full network discovery، subnet inventory، port/version fingerprinting، DNS live queries، firewall/segmentation audit کامل نیست.
- Room migrations، durable resumable queue، history برای project/source audits، evidence object store کامل، signed update pipeline و optional isolated Linux worker هنوز تکمیل نشده‌اند.
- مشخصات 11–23 هنوز دریافت نشده‌اند؛ 22 و 23 در Master Prompt به‌عنوان mandatory specialist specs مشخص شده‌اند و برای ادعای انطباق کامل باید دریافت و جداگانه پیاده‌سازی شوند.
