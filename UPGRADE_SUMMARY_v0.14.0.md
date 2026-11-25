# Upgrade summary — SiteGuard 0.14.0

## Preserved baseline

The v0.14.0 tree was created from the complete v0.13.0 project directory and updated in place. No existing top-level app modules or previous release records were deliberately removed. The former app navigation and all prior source modules remain; the Advanced Hub was added as a new in-app destination.

## New source files

- `app/src/main/java/com/siteguard/app/AdvancedModulesHub.kt`
- `app/src/main/java/com/siteguard/app/AdvancedThreatIntelWorkerV1.kt`
- `app/src/main/java/com/siteguard/app/advanced/MiniJsonV1.kt`
- `app/src/main/java/com/siteguard/app/advanced/LocalReasoningEngineV1.kt`
- `app/src/main/java/com/siteguard/app/advanced/ThreatIntelV1.kt`
- `app/src/main/java/com/siteguard/app/advanced/OsvVulnerabilityLookupV1.kt`
- `app/src/main/java/com/siteguard/app/advanced/WordPressRuntimeClientV1.kt`
- `app/src/main/java/com/siteguard/app/advanced/WebSurfaceAnalyzerV1.kt`
- `app/src/main/java/com/siteguard/app/advanced/AstTaintAnalyzerV1.kt`
- `app/src/main/java/com/siteguard/app/advanced/CloudNetworkPostureV1.kt`
- `app/src/main/java/com/siteguard/app/advanced/BinaryAndroidAnalyzerV1.kt`
- `app/src/main/java/com/siteguard/app/advanced/LocalPatchTransactionV1.kt`
- `app/src/main/java/com/siteguard/app/advanced/ComparativeReportEngineV1.kt`
- `app/src/main/java/com/siteguard/app/advanced/AdvancedAutomationV1.kt`
- `app/src/test/java/com/siteguard/app/advanced/AdvancedModulesTestV1.kt`
- `tools/AdvancedModuleSmoke.kt`
- `tools/run-advanced-smoke-tests.sh`
- `tools/build-release-v0.14.0.sh`

## Existing files updated

- `MainActivity.kt`: adds the advanced center as a separate app destination while retaining previous screens.
- `app/build.gradle.kts`: version 0.14.0 / versionCode 15; current Android SDK and existing dependency set retained.
- `SiteGuardBuildInfo.kt`: version metadata and report schema 8.
- `AdvancedModulesHub.kt`: local encrypted comparison snapshot and comparative PDF/Markdown export.
- `ThreatIntelV1.kt`: strict CISA row-count and date validation.
- `AstTaintAnalyzerV1.kt`: source-line evidence tracking.
- `CloudNetworkPostureV1.kt`: multi-line policy-window detection for Allow + wildcard Action.
- `proguard-rules.pro`: keep rule for the periodic CISA WorkManager worker.
- `.github/workflows/android-ci.yml`: adds JUnit, both lint variants, APK and AAB builds, optional signing verification and artifact checksums.
- `tools/final-release-gate.sh`: validates v0.14 source, selected modules and CI outputs.

## Dependency changes

No new third-party runtime dependency was added in v0.14.0. Existing AndroidX WorkManager 2.12.0 and existing Compose/material dependencies are reused. CISA and OSV use platform HTTP/JSON logic; no hosted AI inference library or API key is required.

## Validation snapshot

- 12/12 standalone JVM smoke tests passed (fixtures/mock transport only).
- 15 new advanced-module JUnit-source methods passed through a temporary local JUnit-API compatibility harness; the official Gradle JUnit task has not been run locally.
- Project test inventory at packaging time: 26 test source files / 153 `@Test` annotations.
- Source release gate: see `LOCAL_RELEASE_GATE_v0.14.0.txt` (20 PASS, 1 WARN).
- Android Gradle/Compose build, lint, APK/AAB creation, signing and device tests remain pending the configured CI run.
