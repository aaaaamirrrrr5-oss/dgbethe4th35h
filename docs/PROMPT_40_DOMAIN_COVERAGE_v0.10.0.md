# ماتریس اجرای پرامت ۱۰۰٬۰۰۰ خطی — SiteGuard Android v0.10.0

## ممیزی ساختار ورودی

پرامت بارگذاری‌شده به‌صورت کامل خوانده و شمارش شد:

- ۱۰۰٬۰۰۰ ردیف؛
- ۴۰ حوزه؛
- ۴۰۰ قابلیت متمایز (۱۰ قابلیت در هر حوزه)؛
- ۲٬۰۰۰ معیار پذیرش متمایز (۵۰ معیار برای هر حوزه)؛
- ۵ مرحله اجرایی، هرکدام شامل ۲۰٬۰۰۰ ردیف: ممیزی، پیاده‌سازی، یکپارچه‌سازی، اعتبارسنجی، پایش/تحویل.

بنابراین تعداد ردیف‌ها به معنی ۱۰۰٬۰۰۰ قابلیت متفاوت نیست؛ ساختار پرامت، ۴۰۰ قابلیت را با ۵۰ معیار و ۵ مرحله ترکیب می‌کند.

## معنای وضعیت‌ها

- **Partial:** بخشی از کد یا گردش‌کار در مخزن وجود دارد، اما معیارهای کامل حوزه اثبات نشده‌اند.
- **Tested:** فقط برای تست مشخصی که واقعاً اجرا و ثبت شده باشد؛ هیچ‌یک از ۴۰ حوزه به‌عنوان یک کل، Tested اعلام نشده است.
- **Unsupported:** در نسخه فعلی ماژول قابل استفاده‌ای برای آن قابلیت وجود ندارد.
- **Blocked:** ادامه اعتبارسنجی به محیط/ابزار بیرونی نیاز دارد و این محیط آن را فراهم نکرده است.

## وضعیت ۴۰ حوزه بر اساس کد و مستندات واقعی

> این ماتریس ادعای اجرای کامل ۲٬۰۰۰ معیار را نمی‌کند. برای هر حوزه مسیرهای واقعی موجود و محدودیت فعلی ثبت شده‌اند. تست‌های ثبت‌شده در نسخه ۰٫۸٫۰، شواهد تاریخی بسته ورودی‌اند و به‌عنوان تست جدید نسخه ۰٫۹٫۰ معرفی نمی‌شوند.

| # | حوزه | فایل‌ها/ماژول‌های موجود | تست/شاهد مرتبط | وضعیت | مانع یا کار باقیمانده |
|---:|---|---|---|---|---|
| 01 | ممیزی مخزن و حفظ سازگاری | `MainActivity.kt`، ۴۰+ فایل `core/`، `SPECIFICATION_GAPS.md`، `TEST_PLAN.md` | `CoreSpecificationContractTest`، آزمون‌های ماژولار | **Partial** | ممیزی منبع و نگاشت قراردادها وجود دارد؛ ماتریس کامل ۴۰ حوزه و اجرای کامل acceptance هنوز انجام نشده است. |
| 02 | رابط Android و Jetpack Compose | `MainActivity.kt`، `OwnershipHygienePanel.kt`، `app/src/main/res/` | تست Compose/دستگاه در این بسته اجرا نشده | **Partial** | UX نسخه ۰٫۹ بهبود یافته، اما build واقعی Compose، screen reader، فونت بزرگ و دستگاه باید اجرا شود. |
| 03 | معماری و قراردادهای مشترک | `PlatformContracts.kt`، `AssessmentWorkflow.kt`، `ExecutionOrderAcceptance.kt` | `CoreSpecificationContractTest`، `ExtendedSpecificationTest` | **Partial** | قراردادها و گردش‌کار وجود دارند؛ versioning و پوشش همه adapterها کامل نیست. |
| 04 | مدل دامنه و ذخیره‌سازی محلی | `LocalAuditHistory.kt`، `LocalSecurityKnowledgeStore.kt`، `LocalDataCipher.kt` | `ExtendedSpecificationTest` | **Partial** | ذخیره‌سازی و رمزنگاری محلی پیاده شده؛ migration/recovery/backup کامل هنوز وجود ندارد. |
| 05 | مجوز، Scope و سیاست امنیتی | `Authorization.kt`، `SecurityPolicyEngine.kt`، `OwnershipProofV1.kt` | `AuthorizationScopeTest`، `OwnershipProofTest` | **Partial** | scope و اعتبار زمانی/دامنه بررسی می‌شود؛ intake کامل engagement و shared egress gate هنوز ناقص است. |
| 06 | ارکستراسیون و چرخه اجرای اسکن | `ScanOrchestrator.kt`، `ScanEngine.kt`، `AssessmentWorkflow.kt` | `WebsiteAnalysisTest`، `CrawlerRobustnessTest` | **Partial** | جریان‌های اصلی وجود دارند؛ صف پایدار و بازیابی کامل پس از مرگ فرایند تضمین نیست. |
| 07 | دارایی‌ها و کشف معماری | `WebsiteDiscoveryEngineV1.kt`، `ProjectArchiveAnalyzer.kt`، `WebsiteSecuritySpecialistEngineV2.kt` | `SpecialistArchiveIntegrationTest` | **Partial** | کشف passive محدود و شواهد ZIP وجود دارد؛ کشف runtime/CDN/origin و معماری کامل وجود ندارد. |
| 08 | خزش passive وب‌سایت | `WebsiteDiscoveryEngineV1.kt` | `CrawlerRobustnessTest`، `ExtendedModulesV080Test` | **Partial** | GET محدود، host/path/time/request bounds و IP pinning پیاده شده؛ sitemap index/robots و coverage گسترده ناقص است. |
| 09 | DNS و TLS و لایه انتقال | `TlsFailureClassifier.kt`، `AddressPolicy` در `ScanEngine.kt`، `NetworkEnterpriseSecurityAnalyzer.kt` | `TlsFailureClassifierTest`، `AddressPolicyTest` | **Partial** | طبقه‌بندی خطای TLS و policy آدرس موجود است؛ enumeration رکورد DNS، cipher/protocol و OCSP/CT ناقص است. |
| 10 | هدرها و کوکی و پیکربندی وب | `PassiveHygieneChecksV1.kt`، `ScanEngine.kt` | `PassiveHygieneChecksTest`، `ExtendedModulesV080Test` | **Partial** | بخشی از hygiene و redaction پیاده شده؛ تحلیل کامل هدر/کوکی و integration در همه گزارش‌ها کامل نیست. |
| 11 | احراز هویت و مجوزدهی برنامه | `Authorization.kt`، `SecurityPolicyEngine.kt`، `SourceCodeAnalyzer.kt` | `AuthorizationScopeTest`، `OwnershipProofTest` | **Partial** | قواعد ایستا و scope محدود وجود دارد؛ BOLA/BFLA و auth runtime چندحسابی اجرا نشده است. |
| 12 | تحلیل ورودی و خروجی و تزریق | `SourceCodeAnalyzer.kt`، `ApiSchemaAnalyzer.kt`، `WordPressSecurityAnalyzer.kt` | `ExtendedSpecificationTest`، `WebsiteSpecialistV2Test` | **Partial** | تحلیل heuristic/signature است؛ AST، taint tracking و dataflow کامل وجود ندارد. |
| 13 | امنیت فایل و آپلود و آرشیو | `ProjectArchiveAnalyzer.kt`، `ArchivePathPolicy` در analyzer | `ArchivePathPolicyTest`، `SpecialistArchiveIntegrationTest` | **Partial** | کنترل ZIP و محدودیت حجم/مسیر در analyzer وجود دارد؛ runtime upload و همه parserها پوشش ندارند. |
| 14 | امنیت REST و OpenAPI | `ApiSchemaAnalyzer.kt`، `GraphQlSoapSchemaAnalyzer.kt` | `ApiSchemaAnalyzerTest`، `ExtendedModulesV080Test` | **Partial** | تحلیل schema و declaration است؛ احراز هویت واقعی endpoint و API DAST اجرا نشده. |
| 15 | امنیت GraphQL و SOAP | `GraphQlSoapSchemaAnalyzer.kt` | `ExtendedModulesV080Test` | **Partial** | SDL/WSDL و نشانه‌های امنیتی schema بررسی می‌شوند؛ resolver runtime، depth/complexity و SOAP operationها اجرا نشده‌اند. |
| 16 | امنیت WordPress | `WordPressSecurityAnalyzer.kt`، `WebsiteSecuritySpecialistEngineV2.kt` | `ExtendedModulesV080Test`، `WebsiteSpecialistV2Test` | **Partial** | تحلیل ایستای PHP و برخی nonce/capability/deserialization signals؛ اتصال read-only احرازشده به وردپرس وجود ندارد. |
| 17 | امنیت WooCommerce | `WordPressSecurityAnalyzer.kt`، `WebsiteSecuritySpecialistEngineV2.kt` | `ExtendedModulesV080Test`، `WebsiteSpecialistV2Test` | **Partial** | نشانه‌های ownership و webhook در سورس؛ business logic runtime و حساب‌های synthetic آزمون نشده‌اند. |
| 18 | تحلیل ایستای PHP | `SourceCodeAnalyzer.kt`، `WordPressSecurityAnalyzer.kt` | `WebsiteSpecialistV2Test`، `ExtendedSpecificationTest` | **Partial** | قواعد heuristic وجود دارد؛ parser/AST/dataflow و تحلیل interprocedural کامل نیست. |
| 19 | تحلیل ایستای JavaScript و TypeScript | `SourceCodeAnalyzer.kt`، `ProjectArchiveAnalyzer.kt` | `ExtendedSpecificationTest` | **Partial** | الگوهای ایستا وجود دارند؛ AST و taint tracking و پیکربندی کامل frameworkها موجود نیست. |
| 20 | وابستگی و SBOM و زنجیره تأمین | `DependencyInventoryAnalyzer.kt`، `ProjectArchiveAnalyzer.kt`، `JsonReportExporter` | `ExtendedSpecificationTest`، `SpecialistArchiveIntegrationTest` | **Partial** | inventory/SBOM موجود است؛ provenance، hash و license تطبیق کامل همه package managerها ندارد. |
| 21 | امنیت شبکه و سازمانی | `NetworkEnterpriseSecurityAnalyzer.kt`، TCP/TLS probe در `MainActivity.kt` | `NetworkEnterpriseSecurityAnalyzerTest`، `AddressPolicyTest` | **Partial** | بررسی محدود و هدف‌مند وجود دارد؛ discovery گسترده و segmentation کامل نیست. |
| 22 | هویت سازمانی AD و Entra و SSO | `CloudConfigurationAnalyzer.kt`، `NetworkEnterpriseSecurityAnalyzer.kt` | تست اختصاصی اتصال زنده موجود نیست | **Partial** | برخی بررسی‌های ایستا/پیکربندی؛ اتصال زنده AD/Entra/Kerberos/SSO پشتیبانی نمی‌شود. |
| 23 | امنیت Cloud و IAM و Storage | `CloudConfigurationAnalyzer.kt`، `ProjectArchiveAnalyzer.kt` | `CloudConfigurationAnalyzerTest` | **Partial** | فقط بررسی فایل پیکربندی؛ اتصال به cloud account و ارزیابی IAM/Storage runtime وجود ندارد. |
| 24 | Container و Kubernetes و IaC و CI/CD | `CloudConfigurationAnalyzer.kt`، `ProjectArchiveAnalyzer.kt` | `CloudConfigurationAnalyzerTest`، `ExtendedSpecificationTest` | **Partial** | تحلیل ایستای manifest/configuration؛ cluster runtime و policy admission اجرا نمی‌شود. |
| 25 | امنیت موبایل Android و APK/AAB | `MobileSecurityAnalyzer.kt`، `ProjectArchiveAnalyzer.kt` | `MobileSecurityAnalyzerTest`، `ExtendedModulesV080Test` | **Partial** | تحلیل source/متادیتا و marker inventory؛ decode کامل AXML/DEX، signature validation و MobSF وجود ندارد. |
| 26 | Red Team دفاعی و MITRE ATT&CK | `DefensiveIntelligence.kt`، `LabSimulation.kt`، `SecurityKnowledgeBase.kt` | `DefensiveIntelligenceTest`، `ExtendedSpecificationTest` | **Partial** | نگاشت دفاعی و fixture مصنوعی؛ exploit/lateral movement یا آزمون واقعی Red Team پشتیبانی نمی‌شود. |
| 27 | Threat Intelligence و advisory feeds | `DefensiveIntelligence.kt`، `SecurityKnowledgeBase.kt`، `LocalSecurityKnowledgePack.kt` | `DefensiveIntelligenceTest` | **Partial** | دانش محلی curated وجود دارد؛ feed زنده CVE/NVD/CISA/OSV و امضای بسته به‌روزرسانی نشده است. |
| 28 | Forensics و chain of custody | `ThreatForensicsEngine.kt`، `PersistentChainOfCustodyLedgerV1.kt`، `LocalAuditHistory.kt` | `ExtendedModulesV080Test`، `ExtendedSpecificationTest` | **Partial** | hash/timeline و زنجیره hash محلی؛ امضای سخت‌افزاری و external witness وجود ندارد. |
| 29 | دانش محلی و Rule Engine | `SecurityKnowledgeBase.kt`، `LocalSecurityKnowledgePack.kt`، `LocalSecurityKnowledgeStore.kt` | `ExtendedSpecificationTest` | **Partial** | جست‌وجوی آفلاین و قواعد deterministic؛ دیتاست کامل/به‌روز و feed امضاشده موجود نیست. |
| 30 | Attack Graph و Risk Engine | `AttackGraphRiskEngine.kt`، `RiskEngine.kt`، `RootCauseAnalyzer.kt` | `DefensiveIntelligenceTest`، `ExtendedSpecificationTest` | **Partial** | گراف شواهد و اولویت‌بندی توضیح‌پذیر؛ امتیاز خطر یا مسیر گراف اثبات exploitability نیست. |
| 31 | اصلاح و Patch و Rollback | `RemediationPatchEngine.kt`، `WebsiteRemediationPlaybook.kt` | `ExtendedSpecificationTest`، `WebsiteSpecialistV2Test` | **Partial** | طرح اصلاح، preview، backup/rollback و retest guide؛ اعمال خودکار production عمداً وجود ندارد. |
| 32 | Automation و WorkManager | `SecurityAutomation.kt`، `ScanOrchestrator.kt` | `ExtendedSpecificationTest` | **Partial** | صف bounded و کنترل لغو؛ WorkManager پایدار، resume کامل و مانیتورینگ همیشه‌روشن وجود ندارد. |
| 33 | Lab و Simulation | `LabSimulation.kt` | `ExtendedSpecificationTest`، اجرای fixtureهای محلی ثبت‌شده در v0.8.0 | **Partial** | سناریوهای مصنوعی آفلاین؛ VM/container disposable lab و اجرای هدف واقعی وجود ندارد. |
| 34 | GitHub Tool Intelligence | `GitHubToolIntelligence.kt`، `BuildReleasePolicy.kt` | تست‌های کلی QA/release | **Partial** | registry و مدل بازبینی ابزار؛ دانلود/اجرای untrusted repository و نصب‌کننده امضاشده خودکار وجود ندارد. |
| 35 | گزارش و Export | `ReportingQualityEngine.kt`، `PlatformContracts.kt`، `MainActivity.kt` | `ExtendedSpecificationTest` | **Partial** | JSON/HTML و اکنون فهرست یکپارچه یافته‌ها؛ PDF و اعتبارسنجی همه round-tripها کامل نیست. |
| 36 | دیتابیس و رمزنگاری و بازیابی | `LocalDataCipher.kt`، `LocalAuditHistory.kt`، `LocalSecurityKnowledgeStore.kt` | `EvidenceSanitizerTest`، `ExtendedSpecificationTest` | **Partial** | رمزنگاری محلی و ذخیره گزارش؛ recovery/backup/migration جامع و تست restore انجام نشده. |
| 37 | Local Linux Worker و IPC | فایل worker/IPC قابل استقرار در بسته موجود نیست | تست مرتبط وجود ندارد | **Unsupported** | worker لینوکس ایزوله، IPC احراز هویت‌شده و sandbox toolchain پیاده نشده است. |
| 38 | Resource و Capability Manager | `DeviceCapabilityDetector.kt`، `BuildReleasePolicy.kt` | تست مستقل resource budget وجود ندارد | **Partial** | تشخیص برخی قابلیت‌های دستگاه؛ بودجه RAM/CPU/disk/battery و throttling کامل نشده. |
| 39 | QA و Benchmark | `app/src/test/java/com/siteguard/app/core/`، `TEST_PLAN.md`، `tools/final-release-gate.sh` | تست‌های unit موجود؛ benchmark جامع موجود نیست | **Partial** | تست‌های هدفمند و source gate؛ Android Gradle/JUnit/lint/device/benchmark در این محیط اجرا نشده. |
| 40 | Build و Release و Privacy | `app/build.gradle.kts`، `.github/workflows/android-ci.yml`، `BuildReleasePolicy.kt`، `tools/` | source release gate در این بسته اجرا می‌شود؛ build Android نه | **Blocked** | نسخه ۰٫۹٫۰ و CI تعریف شده‌اند؛ در این محیط Gradle executable، Android SDK و wrapper JAR موجود نیست، پس APK build/sign/install تأیید نشده است. |

## تغییرات واقعی این ارتقا (v0.9.0)

1. تم مشکی/قرمز حفظ شد و هدر برند، وضعیت اجرای زنده، کارت‌های آماری و سلسله‌مراتب بصری بازطراحی شدند.
2. چهار مقصد ناوبری پایین صفحه حفظ و کنتراست وضعیت انتخاب‌شده و برچسب‌های دسترس‌پذیری بهتر شد.
3. یافته‌های اسکن وب، تحلیل سورس و تحلیل ZIP در یک مجموعه deduplicate و بر اساس شدت مرتب می‌شوند؛ جست‌وجوی عنوان/شناسه/دارایی/CWE و فیلتر شدت نیز اضافه شده است. کارت‌های تکراری از داخل پنل‌های تحلیلی حذف شدند و آمار داشبورد اکنون از همین مجموعه یکپارچه محاسبه می‌شود.
4. جزئیات طولانی Website Security Specialist شامل کنترل‌ها، شواهد، نقشه معماری، طرح آزمون و وابستگی‌ها به‌صورت پیش‌فرض جمع هستند و با اقدام کاربر باز می‌شوند؛ خلاصه و شاخص‌ها همچنان دیده می‌شوند.
5. خروجی JSON از schema نسخه ۳ استفاده می‌کند و آرایه سطح بالای `findings` همه منابع را پوشش می‌دهد. نسخه برنامه ۰٫۹٫۰ و versionCode 10 شد.

## تست‌ها و محدودیت‌های اعتبارسنجی

- نسخه قبلی شامل تست‌های unit و نتایج runner محلی است؛ این فایل‌ها برای حفظ تاریخچه نگه داشته شده‌اند.
- `tools/final-release-gate.sh` در زمان تحویل این نسخه جداگانه اجرا و خروجی آن در `TEST_RESULTS_v0.9.0.txt` ثبت می‌شود.
- محیط فعلی `gradle`، Gradle wrapper JAR، Android SDK و `adb` ندارد. در نتیجه compile واقعی Compose/Android، `:app:testDebugUnitTest`، lint، assembleDebug/Release، امضا، نصب/ارتقا و آزمون screen reader/فونت بزرگ/دستگاه قابل اجرا نیستند و **تأیید نشده‌اند**.
- هیچ AI API، hosted inference، backend اجباری یا تغییر خودکار production اضافه نشده است.


## الحاقیه نسخه v0.10.0 — اصلاحات واقعی و محدوده اثر

این نسخه جایگزین ارزیابی ۴۰ حوزه‌ای قبلی نمی‌شود؛ فقط delta زیر را بر اساس کد و تست‌های افزوده ثبت می‌کند:

| حوزه | فایل‌های تغییرکرده | تغییر واقعی در v0.10.0 | شواهد جدید | وضعیت کل حوزه |
|---:|---|---|---|---|
| 01 | `Authorization.kt`، `EvidenceSanitizer.kt`، `PlatformContracts.kt` | اعتبارسنجی سخت‌گیرانه‌تر manifest/path/host/port و پاک‌سازی متن خروجی | compile مستقل Kotlin و policy smoke tests؛ تست JUnit به بسته افزوده شده ولی Gradle آن اجرا نشده | **Partial** |
| 04 | `SiteGuardBuildInfo.kt`، `PlatformContracts.kt` | نسخه و schema مرکزی؛ پاک‌سازی متن‌های حساس در finding/remediation report | بررسی کد و release gate | **Partial** |
| 05 | `Authorization.kt`، `AuthorizationScopeTest.kt` | رد path traversal و encoding مبهم، زمان نامعتبر، budget/port/host نامعتبر، مرزبندی قطعه مسیر و IDN/IP مبهم | policy smoke tests؛ JUnit source افزوده‌شده | **Partial** |
| 06 | `ScanEngine.kt`، `WebsiteDiscoveryEngineV1.kt`، `MainActivity.kt` | deadline سراسری coroutine و انتشار CancellationException به فراخواننده؛ نمایش پیام timeout در UI | compile مستقل Kotlin با coroutine/JVM و stubs محدود؛ Gradle/device test اجرا نشده | **Partial** |
| 08 | `WebsiteDiscoveryEngineV1.kt` | سقف زمان قابل تنظیم ۵ تا ۱۸۰ ثانیه، checkpoint لغو، و عدم ثبت cancellation به‌عنوان خطای درخواست | compile مستقل Kotlin با stubs محدود | **Partial** |
| 10 | `EvidenceSanitizer.kt`، `EvidenceSanitizerTest.kt`، `PlatformContracts.kt` | redaction credentialهای JSON، header، provider token، PEM، JWT و URL credential پیش از قرارگیری در گزارش | policy smoke tests؛ JUnit source افزوده‌شده | **Partial** |
| 28 | `EvidenceSanitizer.kt`، `PlatformContracts.kt` | کمینه‌سازی افشای credential در evidence/remediation report | policy smoke tests و بررسی release gate | **Partial** |
| 40 | `SiteGuardBuildInfo.kt`، `TEST_RESULTS_v0.10.0.txt` | ثبت نسخه، schema، تست‌های اجراشده و blockerهای build به‌صورت قابل بازبینی | source release gate و خروجی compile/test محلی | **Partial** |

**وضعیت تجمیعی ۴۰ حوزه تغییر نکرده است:** ۳۸ حوزه Partial، یک حوزه Unsupported و یک حوزه Blocked. هیچ حوزه‌ای صرفاً به دلیل وجود کد یا عبور یک smoke test به Tested/Complete ارتقا داده نشده است. ۲٬۰۰۰ معیار پذیرش همچنان به‌طور کامل اجرا و تأیید نشده‌اند.

### محدودیت‌های جدیدی که همچنان باقی‌اند

- `InetAddress.getAllByName` در resolver سیستم یک فراخوانی blocking است؛ timeout coroutine در checkpointها و مرحله socket اعمال می‌شود، اما نمی‌تواند تضمین کند resolver بومی سیستم‌عامل در همه شرایط فوراً interrupt شود.
- آزمون JUnit افزوده شده، اما در این محیط Gradle task آن اجرا نشده است.
- اجرای کامل Android/Compose با SDK، lint، APK، device, RTL/TalkBack و lifecycle هنوز Blocked است.
- تحلیل AST/taint، DAST احرازشده، shared egress gate همه adapterها، صف پایدار و خودکارسازی production همچنان در ماتریس قبلی Partial/Unsupported باقی می‌مانند.
