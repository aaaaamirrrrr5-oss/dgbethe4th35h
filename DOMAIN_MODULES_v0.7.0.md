# SiteGuard Android v0.8.0 — Domain Modules

| حوزه | اجزا | وضعیت پیاده‌سازی | محدودیت/مدرک |
|---|---|---|---|
| UI و Android shell | `MainActivity.kt`, Compose | حفظ‌شده؛ بدون بازطراحی | تغییر فقط برای نمایش گزارش specialist و افزودن جزئیات remediation در همان سبک موجود |
| Passive Website Scan | `ScanEngine`, `ScanOrchestrator`, `WebsiteSecuritySpecialist` | Implemented | یک GET محدود، no redirect/crawl/auth/DAST؛ TLS و header coverage فقط manual review از همین درخواست |
| Engagement / Scope Gate | `WebsiteEngagementManifestV2` | Implemented برای مدل و local validation | legacy UI به شکل user-declared single-host manifest تبدیل می‌شود؛ فرم intake کامل سازمانی و امضای دیجیتال مجوز هنوز وجود ندارد |
| Website Specialist | `WebsiteSecuritySpecialistEngineV2` | Implemented / partial | ماتریس 16 کنترل، per-control test plan، sanitized SHA-256 evidence records، coverage labels، asset/component inventory و architecture graph از archive؛ runtime production را ارزیابی نمی‌کند |
| WordPress/WooCommerce | `WordPressSecurityAnalyzer`, archive analyzer | Partially supported | بررسی deterministic source indicators؛ plugin active state، users/roles، multisite runtime، DB و payment sandbox در دسترس نیست |
| API Security | `ApiSchemaAnalyzer` | Partially supported | OpenAPI/Swagger JSON static؛ GraphQL/SOAP/YAML و full authenticated DAST نیست |
| Source / Dependency | `SourceCodeAnalyzer`, `DependencyInventoryAnalyzer` | Partially supported | source line rules و manifest inventory؛ AST/taint/reachability/advisory exact matching کامل نیست |
| Remediation Playbook | `WebsiteRemediationPlaybookV1` | Implemented templates | 14 recipe؛ الگوها نیازمند تطبیق نسخه/framework/source و human review هستند |
| Patch Preview/Lifecycle | `RemediationPatchEngineV1` | Implemented with gates | فقط snippet یکتا/دقیق؛ backup/staging/rollback به‌صورت plan و lifecycle؛ هیچ production apply ندارد |
| Evidence / Graph | `AttackGraphRiskEngine`, specialist architecture graph | Implemented limited | observed/inferred با provenance؛ architecture فقط از evidenceهای archive ساخته می‌شود، نه شبکه زنده |
| Reporting | `MainActivity`, `ReportingQualityEngine` | Implemented | JSON/HTML با specialist coverage، test plans، evidence digests و architecture relationships؛ PDF ندارد |
| QA / Release | JUnit sources, local smoke, workflow | Partially verified | smoke و source preflight اجرا شده؛ Gradle CI هنوز در repo کاربر اجرا نشده |

## Website Specialist controls

1. TLS/DNS/edge — not tested from source archive.
2. Headers/cookie/cache — not tested unless passive HTTP result is present; then manual review only.
3. Auth/session — not tested without staging accounts.
4. Authorization/BOLA/tenant — manual review for source signals; synthetic runtime tests needed.
5. Input/output/injection — static heuristic/manual review.
6. CSRF/CORS/cache — manual review or not tested.
7. File handling — static code signal/manual review.
8. API schema — OpenAPI JSON only.
9. Commerce — not tested without sandbox/synthetic fixtures.
10. Server/deployment — partial configuration review.
11. WordPress inventory — source-derived, not proof of active runtime plugin.
12. WordPress REST/AJAX — source heuristic/manual review.
13. WooCommerce order ownership — not tested at runtime.
14. WooCommerce webhook — source heuristic/manual review; replay not executed.
15. Dependencies — inventory/SBOM, no current vulnerability claim without exact advisory match.
16. Business logic — not tested without staging/sandbox.

Coverage policy: absence of related findings never sets PASS. Only `CONFIRMED` findings with non-empty evidence, exact asset and exact location can set FAIL; a confirmed label without these fields is `NEEDS_MANUAL_REVIEW`; probable/unverified signals also result in NEEDS_MANUAL_REVIEW. Controls without prerequisites are NOT_TESTED/UNSUPPORTED/NOT_APPLICABLE.
