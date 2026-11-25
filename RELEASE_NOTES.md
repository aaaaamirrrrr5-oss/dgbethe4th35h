# Release Notes — SiteGuard Android v0.13.0

نسخه فعلی: `0.13.0`، versionCode `14`، report schema `7`.

- DNS posture خواندنی برای SPF/DMARC/CAA با DNS-over-HTTPS.
- صف automation ماندگار و رمزگذاری‌شده با authorization re-check، WorkManager پس‌زمینه و اجرای دستی foreground.
- آرشیو محلی رمزگذاری‌شده گزارش‌های وب/سورس/پروژه/DNS و baseline تغییرات ۵۰ دارایی.
- امتیاز توضیح‌پذیر کیفیت شواهد و خروجی PDF چندصفحه‌ای RTL.
- release gate: 19 PASS، 1 WARN؛ JUnit، Gradle build/lint، APK و تست دستگاه اجرا نشده‌اند.
- محدودیت‌های باقیمانده: زمان‌بندی real-time/همیشه‌روشن، اتصال احرازشده WordPress runtime، AST/taint کامل، Cloud/AD runtime و بررسی عمیق باینری.

جزئیات کامل: `RELEASE_NOTES_v0.13.0.md` و `TEST_RESULTS_v0.13.0.txt`.

---

---

# Release Notes — SiteGuard Android v0.8.0

## Added
- GraphQL SDL static review for sensitive query/mutation fields lacking visible access directives, with explicit unverified/manual-review labeling.
- SOAP WSDL parser with DTD and external entity access disabled; HTTP endpoint and missing in-document security metadata observations.
- Line-oriented OpenAPI YAML static review for operation-level/global security declaration gaps. YAML anchors, complex merge behavior and `$ref` resolution are not claimed.
- Bounded passive same-host website crawler: GET-only, per-URL scope re-check, IP pinning, TLS hostname verification, no credentials/forms, no automatic redirects, no external links, bounded depth/pages/body and request budget.
- Query-string rejection at crawler entry and exclusion of `Set-Cookie` response headers from retained evidence.
- Numeric-only IPv4/IPv6 CIDR parser; hostname values are rejected rather than DNS-resolved as network addresses.
- Persistent append-only local SHA-256 hash-linked chain-of-custody ledger with tamper detection.
- Additional WordPress/WooCommerce static indicators for AJAX nonce/capability, request-driven deserialization, object ownership, file editor and secret redaction.
- APK/AAB binary archive inventory signals for binary AndroidManifest/DEX presence (inventory only; no binary decoding/signature verification).
- Runtime specification registry for all 24 specification documents, with per-document implementation status, verified checks and remaining work. Added summary card to the existing dashboard and detail rows to JSON/HTML reports.
- Ten focused v0.8.0 integration checks for the new modules and safety boundaries.

## Preserved
- Existing package/application ID, black/red visual style, dashboard/cards, four-item bottom navigation, existing scanner, code/project archive analysis, WordPress/WooCommerce source review, local knowledge, network/mobile/cloud, graph/risk, forensics, lab and reporting modules.
- No AI API, API key, hosted inference or mandatory backend.

## Changed
- App versionName `0.8.0`, versionCode `9`.
- JSON/HTML report now includes specification coverage 00–23 and local custody-ledger status.
- Website crawler enforces numeric CIDR only, rejects query strings and strips cookie response data from retained evidence.

## Validation performed
- Full `app/src/main/java/com/siteguard/app/core` Kotlin source compilation with the locally installed Kotlin compiler and compatibility stubs for Android/JSON APIs.
- Ten focused integration checks passed in a local runner.
- Source release preflight verifies manifest XML, no known hosted AI endpoint, specification packaging, original UI markers, CI and documentation presence.

## Not validated / limitations
- No Android Gradle build, Android/Compose UI compile against the SDK, JUnit Gradle task, lint, APK assembly, signing, install/upgrade, restore or physical-device test was executed in this environment.
- Full WordPress/WooCommerce runtime, authenticated API DAST, complete AST/taint, cloud/AD runtime, binary APK/AAB decoding, MobSF, PDF export, Linux worker, durable background scheduler and isolated container/VM lab remain partial or unsupported. See `SPECIFICATION_GAPS.md` and `IMPLEMENTATION_MATRIX_00_23.md`.
