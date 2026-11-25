#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0
WARN=0
pass() { printf 'PASS — %s\n' "$1"; PASS=$((PASS+1)); }
warn() { printf 'WARN — %s\n' "$1"; WARN=$((WARN+1)); }
fail() { printf 'FAIL — %s\n' "$1" >&2; exit 1; }

[[ -f "$ROOT/app/src/main/AndroidManifest.xml" ]] || fail 'AndroidManifest.xml is missing'
python3 - "$ROOT/app/src/main/AndroidManifest.xml" <<'PY'
import sys, xml.etree.ElementTree as ET
ET.parse(sys.argv[1])
PY
pass 'Android manifest is well-formed XML'

"$ROOT/tools/check-no-hosted-ai.sh" >/dev/null
pass 'No known hosted AI inference endpoint configured in runtime source'

for n in $(seq -w 0 23); do
  file=$(find "$ROOT/docs/specifications" -maxdepth 1 -type f -name "${n}_*.txt" -print -quit)
  [[ -n "$file" ]] || fail "Specification ${n} missing from docs/specifications"
done
[[ -f "$ROOT/docs/specifications/README_EXECUTION_ORDER.txt" ]] || fail 'README execution order is missing'
pass 'All specifications 00–23 and execution-order README are packaged'

MAIN="$ROOT/app/src/main/java/com/siteguard/app/MainActivity.kt"
grep -q '0xFF090A0D' "$MAIN" || fail 'Original dark background color was not found'
grep -q '0xFFE32645' "$MAIN" || fail 'Original red accent was not found'
grep -q 'NavigationBarItem' "$MAIN" || fail 'Bottom navigation structure was not found'
pass 'Original dark/red UI and bottom navigation markers are retained'

[[ -f "$ROOT/app/src/main/java/com/siteguard/app/core/SpecificationCoverageRegistryV080.kt" ]] || fail 'Specification coverage registry is missing'
[[ -f "$ROOT/IMPLEMENTATION_MATRIX_00_23.md" ]] || fail '00–23 implementation matrix is missing'
[[ -f "$ROOT/SPEC_EXECUTION_LOG_v0.8.0.md" ]] || fail 'v0.8.0 execution log is missing'
grep -q 'expectedDocuments = 24' "$ROOT/app/src/main/java/com/siteguard/app/core/SpecificationCoverageRegistryV080.kt" || fail 'Coverage registry does not declare 24 documents'
pass 'Runtime 00–23 coverage registry, implementation matrix and execution log are present'
[[ -f "$ROOT/SPEC_EXECUTION_LOG_v0.9.0.md" ]] || fail 'v0.9.0 five-stage execution log is missing'
pass 'v0.9.0 five-stage execution log is present'

[[ -f "$ROOT/app/src/main/java/com/siteguard/app/core/GraphQlSoapSchemaAnalyzer.kt" ]] || fail 'GraphQL/WSDL/YAML analyzer is missing'
[[ -f "$ROOT/app/src/main/java/com/siteguard/app/core/WebsiteDiscoveryEngineV1.kt" ]] || fail 'Passive website crawler is missing'
[[ -f "$ROOT/app/src/main/java/com/siteguard/app/core/PersistentChainOfCustodyLedgerV1.kt" ]] || fail 'Local chain-of-custody ledger is missing'
pass 'v0.8.0 specialist, schema-analysis, crawler and forensic modules are present'

[[ -f "$ROOT/docs/PROMPT_40_DOMAIN_COVERAGE_v0.9.0.md" ]] || fail '40-domain prompt coverage matrix is missing'
[[ -f "$ROOT/docs/PROMPT_40_DOMAIN_COVERAGE_v0.10.0.md" ]] || fail 'v0.10.0 prompt coverage delta is missing'
[[ -f "$ROOT/RELEASE_NOTES_v0.10.0.md" ]] || fail 'v0.10.0 release notes are missing'
[[ -f "$ROOT/SPEC_EXECUTION_LOG_v0.10.0.md" ]] || fail 'v0.10.0 execution log is missing'
[[ -f "$ROOT/TEST_RESULTS_v0.10.0.txt" ]] || fail 'v0.10.0 test report is missing'
grep -q '۴۰ حوزه' "$ROOT/docs/PROMPT_40_DOMAIN_COVERAGE_v0.9.0.md" || fail '40-domain prompt coverage matrix lacks its audited domain count'
grep -q '۱۰۰٬۰۰۰ ردیف' "$ROOT/docs/PROMPT_40_DOMAIN_COVERAGE_v0.9.0.md" || fail 'prompt matrix does not record the input size'
grep -q 'allCurrentFindings' "$ROOT/app/src/main/java/com/siteguard/app/MainActivity.kt" || fail 'Unified findings aggregation is missing'
grep -q 'items(visibleFindings' "$ROOT/app/src/main/java/com/siteguard/app/MainActivity.kt" || fail 'Unified findings list is not rendered'
grep -q 'REPORT_SCHEMA_VERSION' "$ROOT/app/src/main/java/com/siteguard/app/MainActivity.kt" || fail 'JSON report schema is not sourced from build metadata'
grep -q 'specialistDetailsExpanded' "$ROOT/app/src/main/java/com/siteguard/app/MainActivity.kt" || fail 'Expandable specialist details are missing'
pass 'v0.9.0 UX, unified findings/reporting and 40-domain prompt matrix are present'

[[ -f "$ROOT/app/src/test/java/com/siteguard/app/core/ExtendedModulesV080Test.kt" ]] || fail 'v0.8.0 focused test source is missing'
[[ -f "$ROOT/TEST_RESULTS_v0.8.0.txt" ]] || fail 'v0.8.0 test results are missing'
pass 'Focused v0.8.0 regression tests and results are present'
[[ -f "$ROOT/app/src/test/java/com/siteguard/app/core/AuthorizationScopeTest.kt" ]] || fail 'Authorization scope regression tests are missing'
[[ -f "$ROOT/app/src/test/java/com/siteguard/app/core/EvidenceSanitizerTest.kt" ]] || fail 'Evidence redaction regression tests are missing'
[[ -f "$ROOT/app/src/test/java/com/siteguard/app/core/WebsiteDiscoveryOptionsTest.kt" ]] || fail 'Website discovery deadline regression tests are missing'
pass 'v0.10.0 authorization, evidence-redaction and crawler-deadline regression tests are present'

VERSION_CODE=$(grep -E 'versionCode\s*=' "$ROOT/app/build.gradle.kts" | grep -oE '[0-9]+' | head -1)
VERSION_NAME=$(grep -E 'versionName\s*=' "$ROOT/app/build.gradle.kts" | sed -E 's/.*"([^"]+)".*/\1/')
[[ "$VERSION_CODE" == '15' && "$VERSION_NAME" == '0.14.0' ]] || fail "Unexpected app version ($VERSION_NAME / $VERSION_CODE)"
pass 'App version metadata is v0.14.0 / versionCode 15'
grep -q '^# SiteGuard Android v0.14.0' "$ROOT/README.md" || fail 'README does not identify v0.14.0 as the current version'
grep -q 'versionCode `15`' "$ROOT/README.md" || fail 'README version code is stale'
pass 'README release metadata matches the application version'
[[ -f "$ROOT/app/src/main/java/com/siteguard/app/core/TlsSessionInfoV1.kt" && -f "$ROOT/app/src/test/java/com/siteguard/app/core/TlsSessionEvaluatorTest.kt" ]] || fail 'v0.11.0 TLS session evaluator or its tests are missing'
grep -q 'REPORT_SCHEMA_VERSION = 8' "$ROOT/app/src/main/java/com/siteguard/app/core/SiteGuardBuildInfo.kt" || fail 'Report schema must be 8 for v0.14.0'
grep -q 'passive_hygiene' "$ROOT/app/src/main/java/com/siteguard/app/MainActivity.kt" || fail 'passive_hygiene JSON section is not exported'
[[ -f "$ROOT/RELEASE_NOTES_v0.11.0.md" && -f "$ROOT/TEST_RESULTS_v0.11.0.txt" ]] || fail 'v0.11.0 release notes or test report are missing'
pass 'v0.11.0 TLS session evaluation, hygiene JSON export and release documents are present'
[[ -f "$ROOT/app/src/main/java/com/siteguard/app/core/HygieneParsersV1.kt" && -f "$ROOT/app/src/test/java/com/siteguard/app/core/HygieneParsersTest.kt" ]] || fail 'v0.12.0 security.txt/HSTS parsers or their tests are missing'
grep -q 'security_txt' "$ROOT/app/src/main/java/com/siteguard/app/core/PassiveHygieneJsonV1.kt" || fail 'security_txt JSON section is missing'
[[ -f "$ROOT/RELEASE_NOTES_v0.12.0.md" && -f "$ROOT/TEST_RESULTS_v0.12.0.txt" ]] || fail 'v0.12.0 release notes or test report are missing'
pass 'v0.12.0 security.txt/HSTS evaluation, JSON export and release documents are present'

[[ -f "$ROOT/app/src/main/java/com/siteguard/app/core/DnsSecurityPostureAnalyzer.kt" ]] || fail 'DNS posture analyzer is missing'
[[ -f "$ROOT/app/src/main/java/com/siteguard/app/core/LocalAssessmentArchive.kt" ]] || fail 'Encrypted assessment archive is missing'
[[ -f "$ROOT/app/src/main/java/com/siteguard/app/core/PersistentAssessmentQueueV1.kt" ]] || fail 'Persistent automation queue is missing'
[[ -f "$ROOT/app/src/main/java/com/siteguard/app/core/EvidenceConfidenceEngine.kt" ]] || fail 'Evidence confidence engine is missing'
[[ -f "$ROOT/app/src/main/java/com/siteguard/app/PdfReportRenderer.kt" ]] || fail 'PDF report renderer is missing'
grep -q 'CreateDocument("application/pdf")' "$ROOT/app/src/main/java/com/siteguard/app/MainActivity.kt" || fail 'PDF export UI is not wired'
grep -q 'DnsSecurityPostureAnalyzerV1.analyze' "$ROOT/app/src/main/java/com/siteguard/app/MainActivity.kt" || fail 'DNS posture analyzer is not wired into UI'
grep -q 'automationQueue.claimDue' "$ROOT/app/src/main/java/com/siteguard/app/MainActivity.kt" || fail 'Foreground automation execution is not wired'
pass 'v0.13.0 DNS posture, encrypted assessment archive, persisted queue, evidence scoring and PDF export are wired'
[[ -f "$ROOT/app/src/main/java/com/siteguard/app/AssessmentQueueWorkerV1.kt" ]] || fail 'WorkManager assessment worker is missing'
grep -q 'androidx.work:work-runtime-ktx:2.10.0' "$ROOT/app/build.gradle.kts" || fail 'WorkManager stable dependency is missing'
grep -q 'setRequiredNetworkType(NetworkType.CONNECTED)' "$ROOT/app/src/main/java/com/siteguard/app/AssessmentQueueWorkerV1.kt" || fail 'WorkManager network constraint is missing'
grep -q 'cancelAllWorkByTag' "$ROOT/app/src/main/java/com/siteguard/app/AssessmentQueueWorkerV1.kt" || fail 'WorkManager emergency cancellation is missing'
grep -q 'SiteGuardAssessmentWorkerV1' "$ROOT/app/proguard-rules.pro" || fail 'R8 keep rule for WorkManager worker is missing'
pass 'WorkManager background scheduling, network constraints, retry/cancellation and R8 worker retention are wired'
[[ -f "$ROOT/app/src/main/java/com/siteguard/app/core/SiteGuardBuildInfo.kt" ]] || fail 'Central build metadata is missing'
grep -q 'maxDurationMs: Long = 60_000L' "$ROOT/app/src/main/java/com/siteguard/app/core/WebsiteDiscoveryEngineV1.kt" || fail 'Crawler global time budget is missing'
grep -q 'catch (cancelled: CancellationException)' "$ROOT/app/src/main/java/com/siteguard/app/core/ScanEngine.kt" || fail 'Scan cancellation propagation is missing'
grep -q 'ambiguousEncoding' "$ROOT/app/src/main/java/com/siteguard/app/core/Authorization.kt" || fail 'Encoded path validation is missing'
grep -q 'manifest.allowedMethods != setOf("PASSIVE_HTTP_GET")' "$ROOT/app/src/main/java/com/siteguard/app/core/Authorization.kt" || fail 'Passive-only method allowlist is missing'
grep -q 'jsonQuotedAssignment' "$ROOT/app/src/main/java/com/siteguard/app/core/EvidenceSanitizer.kt" || fail 'JSON credential redaction is missing'
grep -q 'plan.proposedPatchDiff?.let { safeReportText(it' "$ROOT/app/src/main/java/com/siteguard/app/core/PlatformContracts.kt" || fail 'Remediation patch report redaction is missing'
pass 'v0.10.0 authorization, timeout/cancellation and evidence-redaction hardening is present'

for f in \
  "$ROOT/.github/workflows/android-ci.yml" \
  "$ROOT/THREAT_MODEL.md" \
  "$ROOT/TEST_PLAN.md" \
  "$ROOT/SBOM_STATUS.md" \
  "$ROOT/SPECIFICATION_GAPS.md" \
  "$ROOT/RELEASE_NOTES.md" \
  "$ROOT/BUILD_APK_GUIDE_FA.md"; do
  [[ -f "$f" ]] || fail "Release deliverable missing: $(basename "$f")"
done
pass 'CI, threat model, test plan, SBOM and release documentation are present'

grep -q 'android:usesCleartextTraffic="false"' "$ROOT/app/src/main/AndroidManifest.xml" || fail 'Manifest must set usesCleartextTraffic=false'
grep -q 'android:networkSecurityConfig' "$ROOT/app/src/main/AndroidManifest.xml" || fail 'Manifest must reference a networkSecurityConfig'
[[ -f "$ROOT/app/src/main/res/xml/network_security_config.xml" && -f "$ROOT/app/src/main/res/mipmap-anydpi-v26/ic_launcher.xml" ]] || fail 'res/ network config or launcher icon missing'
[[ -f "$ROOT/app/proguard-rules.pro" ]] && grep -q 'isMinifyEnabled = true' "$ROOT/app/build.gradle.kts" || fail 'R8/shrink configuration missing'
pass 'Step 5 hardening: no cleartext, network security config, resources/icon, R8 present'
if [[ -f "$ROOT/gradle/wrapper/gradle-wrapper.jar" && -f "$ROOT/gradlew" ]]; then pass 'Gradle wrapper is committed'; else warn 'Gradle wrapper jar/gradlew missing: run ./gradlew (or tools/bootstrap-wrapper.sh) once to generate the official wrapper and commit the result'; fi

for f in \
  "$ROOT/RELEASE_NOTES_v0.13.0.md" \
  "$ROOT/UPGRADE_SUMMARY_v0.13.0.txt" \
  "$ROOT/TEST_RESULTS_v0.13.0.txt" \
  "$ROOT/SPEC_EXECUTION_LOG_v0.13.0.md"; do
  [[ -f "$f" ]] || fail "v0.13.0 release document missing: $(basename "$f")"
done
[[ -f "$ROOT/app/src/test/java/com/siteguard/app/core/DnsSecurityPostureAnalyzerTest.kt" ]] || fail 'DNS posture regression tests are missing'
[[ -f "$ROOT/app/src/test/java/com/siteguard/app/core/EvidenceConfidenceEngineTest.kt" ]] || fail 'Evidence confidence regression tests are missing'
[[ -f "$ROOT/app/src/test/java/com/siteguard/app/core/AutomationRecoveryTest.kt" ]] || fail 'Automation recovery regression tests are missing'
pass 'v0.13.0 release documents and focused regression test sources are present'

for f in \
  "$ROOT/RELEASE_NOTES_v0.14.0.md" \
  "$ROOT/UPGRADE_SUMMARY_v0.14.0.md" \
  "$ROOT/TEST_RESULTS_v0.14.0.md" \
  "$ROOT/IMPLEMENTATION_MATRIX_v0.14.0.md" \
  "$ROOT/BUILD_RELEASE_GUIDE_v0.14.0_FA.md" \
  "$ROOT/LOCAL_TEST_RUNS_v0.14.0.txt" \
  "$ROOT/LOCAL_JUNIT_SOURCE_RUNS_v0.14.0.txt"; do
  [[ -f "$f" ]] || fail "v0.14.0 deliverable missing: $(basename "$f")"
done
for f in \
  MiniJsonV1.kt LocalReasoningEngineV1.kt ThreatIntelV1.kt OsvVulnerabilityLookupV1.kt \
  WordPressRuntimeClientV1.kt WebSurfaceAnalyzerV1.kt AstTaintAnalyzerV1.kt CloudNetworkPostureV1.kt \
  BinaryAndroidAnalyzerV1.kt LocalPatchTransactionV1.kt ComparativeReportEngineV1.kt AdvancedAutomationV1.kt; do
  [[ -f "$ROOT/app/src/main/java/com/siteguard/app/advanced/$f" ]] || fail "Advanced module missing: $f"
done
ADVANCED_JUNIT_COUNT=$(grep -c '@Test' "$ROOT/app/src/test/java/com/siteguard/app/advanced/AdvancedModulesTestV1.kt")
[[ "$ADVANCED_JUNIT_COUNT" == '15' ]] || fail "Expected 15 advanced JUnit test methods, found $ADVANCED_JUNIT_COUNT"
pass '15 advanced JUnit-source methods are present; local harness run is recorded, official Gradle/JUnit remains pending'
[[ -f "$ROOT/app/src/main/java/com/siteguard/app/AdvancedModulesHub.kt" ]] || fail 'Advanced dashboard not wired'
[[ -f "$ROOT/app/src/main/java/com/siteguard/app/AdvancedThreatIntelWorkerV1.kt" ]] || fail 'CISA WorkManager refresh worker missing'
grep -q 'bundleRelease' "$ROOT/.github/workflows/android-ci.yml" || fail 'CI does not build AAB'
grep -q 'siteguard-comparative-report.pdf' "$ROOT/app/src/main/java/com/siteguard/app/AdvancedModulesHub.kt" || fail 'Comparative PDF export is not wired'
grep -q 'CisaKevRefreshWorkerV1' "$ROOT/app/proguard-rules.pro" || fail 'R8 keep rule for Threat Intelligence worker is missing'
pass 'v0.14.0 advanced modules, dashboard, PDF comparison, WorkManager worker and APK/AAB CI are packaged'

# --- regression gates added after the static review (security-relevant invariants) ---
C="$ROOT/app/src/main/java/com/siteguard/app"
[[ -f "$C/core/PinnedHttpsClientV1.kt" ]] || fail 'Pinned HTTPS client is missing'
grep -q 'PinnedHttpsClientV1.get' "$C/advanced/WordPressRuntimeClientV1.kt" || fail 'WordPress client must use the pinned transport by default'
grep -q 'PinnedHttpsClientV1.get' "$C/advanced/WebSurfaceAnalyzerV1.kt" || fail 'Web surface analyzer must use the pinned transport by default'
grep -q 'AuthorizationBudget.consume' "$C/core/ScanEngine.kt" || fail 'Request budget must be enforced inside ScanEngine (single network choke point)'
if grep -q 'AuthorizationBudget.consume' "$C/core/ScanOrchestrator.kt"; then fail 'ScanOrchestrator must not also consume the budget (double counting)'; fi
grep -q 'attachStore' "$C/MainActivity.kt" || fail 'Authorization budget persistence is not attached in MainActivity'
grep -q 'attachStore' "$C/AssessmentQueueWorkerV1.kt" || fail 'Authorization budget persistence is not attached in the worker'
[[ -f "$ROOT/app/src/test/java/com/siteguard/app/core/PinnedHttpsClientV1Test.kt" && -f "$ROOT/app/src/test/java/com/siteguard/app/advanced/AdapterTransportFixesTest.kt" ]] || fail 'Transport regression tests are missing'
grep -q 'dataExtractionRules' "$ROOT/app/src/main/AndroidManifest.xml" || fail 'Android 12+ data extraction rules are missing'
grep -q 'FLAG_SECURE' "$C/MainActivity.kt" || fail 'FLAG_SECURE hardening is missing'
grep -q 'isDebuggable = false' "$ROOT/app/build.gradle.kts" || fail 'Release build must be explicitly non-debuggable'
pass 'pinned transport, single-choke-point budget and persisted budget invariants hold'

printf '\nLOCAL RELEASE GATE: %s PASS, %s WARN\n' "$PASS" "$WARN"
printf 'Source preflight only. It does not replace Android Gradle build, lint, install, signing or device tests.\n'

