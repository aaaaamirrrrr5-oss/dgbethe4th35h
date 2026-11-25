# Test Plan — SiteGuard Android v0.8.0

## New Website Specialist tests

1. Engagement manifest required fields, proof reference, time window, exact host list, port range, path traversal rejection, request limits and deterministic SHA-256 canonicalization.
2. Scope tests for allowed exact hostname/path/port, denied subdomain, excluded host/path, denied port, unsupported test class, expired scope and exhausted request budget.
3. Dangerous/lab checks: destructive tests blocked outside lab; authenticated synthetic testing requires at least two synthetic identities; staging validation requires staging/lab environment.
4. Coverage semantics: no finding must never set PASS; confirmed finding may set FAIL; probable signal becomes Needs Manual Review; missing runtime prerequisites become Not Tested; non-WP archive marks WP controls Not Applicable.
5. Passive HTTP coverage: one GET must not claim auth, tenant isolation, checkout, API DAST or other runtime controls were tested.
6. Architecture graph: component/dependency edges require evidence reference; observed/inferred labels must remain separate.
7. Playbook mapping: IDOR, SQLi, XSS, CSRF, CORS, headers/CSP, auth/session, file handling, SSRF, WP, WooCommerce, rate limit, dependencies/secrets and generic patch acceptance map to appropriate recipes.
8. Remediation plan output includes containment, root-cause pattern, framework-specific fix, regression, staging, backup, rollback, residual risk, downtime, owner and monitoring.
9. Patch path safety rejects absolute, Windows drive, backslash, traversal and non-unique snippet. No auto-apply path exists.
10. Report export escapes HTML, carries specialist coverage, test plans and sanitized evidence integrity references, and preserves limitations.
11. Evidence quality: Confirmed labels without non-empty evidence, affected asset and exact location must not produce a specialist FAIL state.
12. Evidence sanitization and integrity: secret-like strings are redacted before SHA-256 digest; source-only evidence has zero network telemetry.
13. Test-plan generation: each catalog control has preconditions, risk, criteria, test class and status; active controls remain NOT_EXECUTED without engagement authorization.
14. WordPress applicability: WooCommerce order/webhook checks are Not Applicable for a WordPress-only archive.

## Existing regression suites retained

- Authorization scope and request budgets.
- ZIP path traversal/size and no extraction.
- Website/WordPress/source, API schema, mobile, network, cloud/IaC, dependency inventory, local knowledge, evidence sanitization, attack graph, remediation lifecycle, forensic chain, automation, lab and release preflight.

## Commands for CI

```bash
./tools/check-no-hosted-ai.sh
./tools/final-release-gate.sh
gradle --no-daemon :app:testDebugUnitTest :app:lintDebug :app:assembleDebug :app:assembleRelease
```

## Device verification still required

Install and upgrade on minSdk/API target devices; verify dark/red UI and existing bottom navigation; inspect screen reader/scaled fonts; test Android API levels and ABIs; low-memory/thermal/battery handling; process death/cancellation; local storage encryption; backup/restore; offline mode; network traffic capture; debug/release signing. None of these device checks are represented by the local source smoke test.


## v0.8.0 focused regression suite

`ExtendedModulesV080Test.kt` adds tests for GraphQL SDL authorization indicators, secure WSDL parsing and HTTP endpoints, OpenAPI YAML security declarations, numeric-only CIDR validation, local custody-chain tamper detection, bounded pinned-IP passive crawler behavior, Set-Cookie redaction, WordPress/WooCommerce static review and secret redaction, query-string rejection before network access, and the ordered 00–23 coverage registry. The local compatibility runner executes ten checks, including request-budget accounting when a network attempt fails. These tests are not Gradle JUnit/device tests.

## v0.9.0 dashboard and unified-results acceptance (device/CI required)

1. Confirm black/red palette, branded header and all four existing bottom-navigation destinations render on compact and large screens.
2. Confirm current activity badge reflects the active operation and returns to an idle/last-result state after success, failure or cancellation.
3. Run a web scan, a source-file audit and a ZIP project audit in separate sessions; verify each source's findings appear once in the common results list and the source counts match the originating audit outputs.
4. Verify the common result list sorts Critical, High, Medium, Low and Info in that order; a duplicate rule ID at a different asset/location must not hide a separate result.
5. Search by finding title, ID, affected asset/path and CWE; clear search and verify the original result set returns.
6. Exercise All, Severe, Medium and Low/Info filters; verify empty-filter state is not presented as an assessment result or security pass.
7. Expand/collapse Website Security Specialist detail; ensure controls, reasons, architecture evidence, test plans, limitations, defensive techniques and dependency/SBOM actions remain reachable.
8. Export JSON and HTML after mixed-source assessments; compare the top-level unified findings with the visible common list and ensure evidence is sanitized.
9. Inspect TalkBack/screen-reader labels, 1.3×–2.0× font scaling, RTL Persian rendering, landscape layout and touch target sizes.
10. Verify process recreation and back/scroll behavior do not lose critical in-progress state or leave bottom-navigation selection misleading.

These are acceptance steps to execute on a real Android SDK/device; they have not been claimed as passed in this source-only environment.


## v0.13.0 focused tests

- `DnsSecurityPostureAnalyzerTest`: missing/weak/duplicate SPF and DMARC, CAA presence, invalid host input; resolver injected to avoid live network in unit tests.
- `EvidenceConfidenceEngineTest`: score ordering and false-positive floor; score is explicitly not CVSS or exploit probability.
- `AutomationRecoveryTest`: interrupted RUNNING task recovery, authorization expiry re-check and emergency-stop persistence across scheduler snapshot restore.
- Device acceptance still required: PDF Persian glyph shaping/pagination, encrypted archive retention/clear, DNS resolver connectivity/privacy disclosure, foreground schedule/restart behavior, dark RTL UI and Android API-level compatibility.

## v0.14.0 selected-module acceptance tests

### Executed local JVM smoke tests

`./tools/run-advanced-smoke-tests.sh` compiles the platform-independent advanced Kotlin modules and runs 12 fixture/mocked-network checks. In addition, the 15 methods in `AdvancedModulesTestV1.kt` were compiled and invoked using a temporary local JUnit-API compatibility harness; see `LOCAL_JUNIT_SOURCE_RUNS_v0.14.0.txt`. The harness is not the official JUnit runner. Neither local suite compiles Android/Compose sources or makes live network calls.

### JUnit/CI tests to run

1. `:app:testDebugUnitTest` — includes 15 v0.14 `AdvancedModulesTestV1` test methods plus retained earlier test suites.
2. `:app:lintDebug` and `:app:lintRelease` — confirm Android resources, Compose APIs, permissions and release configuration.
3. `:app:assembleDebug`, `:app:assembleRelease`, `:app:bundleRelease` — confirm compiler/resource/R8 paths and APK/AAB output.
4. With signing secrets supplied, verify APK with `apksigner` and AAB with `jarsigner`; otherwise mark release artifacts unsigned.
5. Install/upgrade on minSdk 26 and current Android 35+ emulator/device; exercise all previous destinations and Advanced Hub tabs.
6. Network integration in a controlled staging environment: CISA/OSV TLS/error/timeout/cache behavior, WP least-privilege REST access, redirect/DNS rebinding controls, rate limits and response-size bounds.
7. Adversarial APK/archive corpus: malformed AXML, duplicate ZIP names, compression bombs, oversize DEX, invalid offsets and unsupported AAB splits.
8. Patch lifecycle: concurrent edits, crash between stages, rollback conflict, symlinks, path traversal and permissions.
9. WorkManager: process death, reboot, constraints, retry, cancellation, duplicate enqueue and no credential persistence.
10. Comparative reporting: corrupted encrypted snapshots, wrong key, schema migration, duplicate IDs and scope drift.

### Actual execution boundary

No Android Gradle/SDK, Compose compile, official JUnit Gradle task, lint, assemble, R8, signing, emulator/device, live site, or live threat-feed integration test is claimed by the local report. The 15 source test methods ran only through a local JUnit-API compatibility harness. The workflow is configured but must be run in GitHub Actions before release sign-off.

