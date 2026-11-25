# SiteGuard Android 0.14.0

## Release scope

This release adds an Advanced Security Hub while retaining the v0.13.0 codebase and earlier modules. The upgrade is additive: legacy passive website assessment, source/project archive analysis, DNS posture, TLS/network checks, encrypted history, evidence scoring, PDF reporting, authorization scope controls and the existing automation queue remain in the project.

## Added

- **Local reasoning:** deterministic, evidence-led prioritization with linked findings, confidence weighting and remediation/validation suggestions. This is local rule-based decision support, not an LLM or trained model.
- **Threat intelligence:** bounded HTTPS CISA Known Exploited Vulnerabilities feed parser/cache and optional daily WorkManager refresh; public OSV.dev package+version query for supported ecosystems.
- **WordPress/WooCommerce runtime:** explicit-consent, HTTPS-only, read-only WordPress REST inspection for the current user, settings, plugins, themes and WooCommerce system status. Application Passwords are short-lived in memory and cleared by the UI after the request.
- **Website/API surface:** six same-origin GET paths, response-header posture checks, standard OpenAPI path discovery and bounded responses.
- **AST/Taint approximation:** bounded lexical/statement/scope representation and source-to-sink tracing across common language patterns.
- **Cloud/network configuration:** static IaC checks for Kubernetes, Terraform, Docker, TLS, public ingress/storage, wildcard IAM and unpinned CI actions.
- **Android binary inspection:** bounded ZIP/APK inspection, binary AndroidManifest string-pool decoding, selected manifest attributes, permissions, components and DEX URL string indicators.
- **Remediation transaction:** exact-match local patch preview, SHA-256 precondition, private workspace apply, backup integrity validation and guarded rollback.
- **Comparative reports:** new/resolved/changed/stable classification, encrypted local snapshots and Markdown/PDF export.
- **Advanced dashboard:** separate in-app hub with dedicated tabs for the selected capabilities.
- **CI release pipeline:** JUnit, debug/release lint, debug/release APK and release AAB tasks; optional Gradle-managed signing when repository secrets are configured.
- **Local regression tests:** 12 platform-independent JVM smoke cases passed; the 15 advanced JUnit-source methods also compiled and passed through a temporary local JUnit-API compatibility harness. The official Gradle/JUnit runner still requires CI execution.

## Security decisions

- No exploit, brute force, write request, production patch or remote configuration change is performed by the new modules.
- WordPress and web modules require explicit in-app authorization. Private-network targets are denied by default and require a separate explicit staging checkbox.
- WordPress credentials are not persisted for background automation. File-based jobs remain interactive until persisted document permissions and safe storage are implemented.
- Only the fixed CISA KEV endpoint is used by the feed updater. OSV lookups send package/ecosystem/version fields to the fixed OSV query endpoint.
- Patch apply/rollback is confined to the app-managed local workspace, never a remote website or cloud account.

## Known limits

- The reasoning engine is deterministic and rule-based; no on-device generative model is bundled.
- CISA data is protected by HTTPS and validated for size/schema/date/CVE/count. No separate end-to-end signed-feed verification is implemented.
- WordPress/WooCommerce checks are read-only and depend on site REST availability and the account's capabilities. DNS addresses are checked before requests but are not pinned at the socket layer, so this is not a complete DNS-rebinding defense.
- Website analysis is passive GET-only, limited to six paths and does not provide full DAST, authentication/authorization testing or business-logic testing.
- The source analyzer is not compiler-grade AST, has no complete call graph, alias analysis or interprocedural taint tracking.
- Cloud checks are static configuration checks, not live Cloud account/IAM/runtime inspection. Existing DNS/TLS/network modules remain separate.
- Android analysis decodes selected APK binary manifests and scans bounded DEX strings. It does not cryptographically verify APK v2/v3/v4 signatures, decompile DEX, disassemble native libraries or run a sandbox. AAB/split-module analysis is limited.
- Automation is not universal: the existing authorized passive website queue and the new daily CISA refresh are scheduled; WordPress and user-selected files remain interactive.
- The Gradle Wrapper JAR/scripts are not included. CI provisions Gradle 8.9 explicitly. GitHub Actions use version tags rather than immutable commit SHAs. A full Android Gradle build, official JUnit Gradle task, lint, signing, AAB build and device test were not executed in the authoring container.

## Version metadata

- `versionName`: `0.14.0`
- `versionCode`: `15`
- `REPORT_SCHEMA_VERSION`: `8`

## Post-release fix — archive size-limit handling (ProjectArchiveAnalyzer)

- **Behavior change:** a single ZIP entry larger than the per-entry cap (512 KB) is now drained without being retained and skipped; the scan continues with the remaining entries. Previously one large image or minified bundle aborted the entire analysis.
- **Unchanged / still fatal:** the archive-wide expanded-size budget (default 20 MB). Exceeding it still stops the scan and adds the resource-cap limitation, so decompression-bomb protection is preserved. Oversized entries still count toward this budget while being drained.
- **Reporting:** an oversized source/config entry is listed in `skippedEntries`; oversized ignored (non-source) entries are skipped silently.
- Tests: `ArchivePathPolicyTest` now covers (1) oversized ignored entry does not abort, (2) oversized source entry is reported and scan continues, (3) total-budget overflow still stops the scan. The old test `enforcesExpandedSizeLimitEvenForIgnoredZipEntries` was replaced because it asserted the previous, too-strict behavior.
- Follow-up hardening in the same fix: directory entries such as `src/` are no longer misreported as unsafe paths; duplicate ZIP entry names keep the first occurrence and report the rest (previously the later one overwrote the earlier and inflated `filesScanned`); `filesDiscovered` no longer counts the entry that tripped the entry cap; the per-finding SHA-256 prefix is computed once per file. Added test `directoryEntriesAreNotReportedAsUnsafe`.
- **Build bootstrap:** the source package had no Gradle wrapper, so `./gradlew` did not exist. Added `gradlew` / `gradlew.bat` bootstrap stubs and made `tools/bootstrap-wrapper.sh` work without a preinstalled Gradle (it downloads the official Gradle 8.9 from services.gradle.org, verifies its published SHA-256, then runs `gradle wrapper`). The first `./gradlew` run therefore generates the official wrapper JAR and scripts, replacing the stubs; commit the result. The bootstrap needs JDK 17+ and network access once. Not executed here (no network); only syntax and the offline failure path were checked.
- **Static consistency audit (no compiler available):** no duplicate top-level declarations in the same package, no unresolved `com.siteguard.app` imports, and the Compose helper functions referenced by `MainActivity`/`AdvancedModulesHub` all exist. `compileSdk = 35` is compatible with the declared WorkManager 2.12.0 (documented requirement: compileSdk 33+, minSdk 24+; the app's minSdk is 26). This audit does not replace `:app:testDebugUnitTest`, lint or an APK build.
- **Background worker fix (`SiteGuardAssessmentWorkerV1`):** when Android stopped a running assessment (network constraint lost, timeout), the task was marked FAILED and never retried, so a scheduled assessment could be silently lost. An OS-initiated stop now re-queues the task within its existing retry budget. It is not re-queued after Emergency Stop, and a task the user cancelled stays cancelled. Not covered by a unit test (the worker needs the Android runtime) and not executed here; verify on a device/emulator by toggling airplane mode during a queued run.
- **Scan engine fix (`ScanEngine`) for IDN hosts and non-ASCII paths:** scope validation accepted Unicode hosts/paths, but the request used the raw Unicode host for DNS, SNI, certificate verification and the Host header, and wrote the request line as US-ASCII (non-ASCII characters became `?`). Internationalized domain names therefore failed or reached the wrong virtual host, and a non-ASCII path could be sent as a different resource than the one that was authorized. The engine now uses the canonical ASCII (punycode) host everywhere and percent-encodes non-ASCII path/query characters as UTF-8. Added `ScanRequestTargetTest`. Verified only through a standalone JVM check of the encoding and IDN conversion; Kotlin compilation and a live scan against an IDN host were not run here.
- **Scan engine fix (`ScanEngine`) — address fallback:** the engine connected only to the first DNS answer, so an unreachable first address (typically an AAAA record on a network without IPv6) failed the whole scan even when other addresses worked. It now tries up to 3 resolved addresses in order. All of them have already passed scope, policy and private-range checks before any connection, so the safety gates are unchanged. Only connection-level failures (refused, no route, timeout) fall through to the next address; no HTTP request is sent on a failed connect, TLS validation failures are still reported rather than retried, and `connectedAddress` records the address actually used. Per-attempt connect timeout is 5 s when several addresses exist (8 s with one) so the total stays within the 26 s scan deadline. Not covered by an automated test (needs sockets/DNS) and not executed here.
- **New check — secrets in `.env` files:** ZIP/source analysis previously ignored `.env` files completely (no matching extension) and its secret rule required quoted values, so unquoted dotenv secrets were never found. `.env`, `.env.<name>` and `<name>.env` are now scanned for secret-named variables (`*PASSWORD*`, `*SECRET*`, `*TOKEN*`, `*API_KEY*`, etc.) with a non-placeholder value of 8+ characters (placeholders such as `changeme`, `your_…`, `${VAR}`, all-digit values and template files `.env.example`/`.env.sample`/`.env.dist` are ignored). Findings are `SG-CODE-ENV-001` (HIGH, CWE-798, PROBABLE); the evidence keeps only the variable name and never the value. `.env` files are not counted as a programming language so they do not inflate input/output coverage. Added `EnvFileAnalysisTest`. The rule logic was simulated outside Kotlin; the Kotlin code itself was not compiled or run here.
