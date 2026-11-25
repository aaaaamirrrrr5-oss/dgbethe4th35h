# Test report — SiteGuard Android 0.14.0

## Executed in this environment

- Host Java: OpenJDK 21.0.12.
- Host Kotlin command-line compiler: kotlinc-jvm 1.9.0.
- Command: `./tools/run-advanced-smoke-tests.sh`.
- Result: **12/12 passed**.
- The test command compiled `core/Authorization.kt` and all pure JVM files in `app/src/main/java/com/siteguard/app/advanced/`, then ran a standalone fixture suite. Compiler output contained JDK deprecation warnings for Java's `URL(String)` constructor; no Kotlin compilation errors were reported.

### Smoke cases passed

1. Bounded JSON parsing, escaping, duplicate-key rejection and trailing-data rejection.
2. Local reasoning priorities a critical finding and keeps the score bounded.
3. CISA KEV fixture parsing and rejection of invalid dates/count mismatch.
4. OSV fixed HTTPS endpoint, POST body escaping and response parsing using a mocked connection.
5. WordPress HTTP/plaintext input rejected before a network factory is called.
6. Loopback web target rejected before a network factory is called.
7. PHP request-source to SQL-query taint flow detected with source/sink line numbers.
8. Cloud privileged/public-ingress/multi-line wildcard IAM indicators detected.
9. Synthetic Android binary XML manifest decoded; ZIP path traversal rejected.
10. Local patch apply and rollback passed; rollback refused to overwrite a subsequent user edit.
11. Comparative report classified new, resolved, changed and unchanged records correctly.
12. Automation policy blocked persisted WordPress credentials and non-persisted file grants while allowing public feed refresh.

The exact command output is stored in `LOCAL_TEST_RUNS_v0.14.0.txt`.

## Test source inventory

- 15 JUnit-source test methods in `AdvancedModulesTestV1.kt` were compiled and invoked successfully through a temporary local JUnit-API compatibility harness: **15/15 passed**. The harness uses the JUnit annotation/assertion API shape but is not the official JUnit runner and does not replace the Gradle JUnit task. The exact method output is `LOCAL_JUNIT_SOURCE_RUNS_v0.14.0.txt`.
- Across the project, 26 test source files contain 153 `@Test` annotations. This is a source inventory count; only the 15 advanced methods and 12 smoke cases listed here were executed locally.

## Source release gate

`tools/final-release-gate.sh` validates project metadata, the v0.14 README, retained previous modules, Android manifest XML, security configuration, WorkManager retention, the advanced module source set, JUnit source inventory, CI AAB task and release documents. The recorded result is stored in `LOCAL_RELEASE_GATE_v0.14.0.txt`: 22 PASS and 1 WARN (missing Gradle Wrapper).

## Not executed / not claimed

- **Android Gradle build:** not run. The authoring container has no `gradle` executable, no `gradlew` script and no `gradle-wrapper.jar`.
- **Android SDK/resource linking:** not run. No Android SDK/build-tools installation was available in this environment.
- **Official Gradle/JUnit suite:** `:app:testDebugUnitTest` was not run; the 15 advanced test methods were instead invoked through the documented local compatibility harness. The official runner still needs CI verification.
- **Compose compilation, Lint, R8/minification, `assembleDebug`, `assembleRelease` and `bundleRelease`:** not verified locally.
- **APK/AAB signing and signature verification:** not run.
- **Device/emulator install, UI automation, battery/memory/performance and accessibility tests:** not run.
- **Live CISA/OSV/WordPress/site HTTP calls:** not run. The smoke tests used fixture JSON or mocked HTTP and checked deny-before-network paths; this environment did not provide reliable external networking/DNS.
- **Real vendor APK validation:** not run; the AXML test used a synthetic manifest fixture.

The workflow `.github/workflows/android-ci.yml` provisions JDK 17, Android SDK 35 and Gradle 8.9, then runs JUnit, lint, debug/release APK and release AAB tasks. Release artifacts are signed only when all four `SITEGUARD_*` signing secrets are configured; otherwise the workflow produces unsigned release artifacts. The CI workflow has not been executed from this chat, so its result must be confirmed after pushing the source to GitHub.

## Addendum — archive size-limit fix

- Source files changed: `ProjectArchiveAnalyzer.kt`, `ArchivePathPolicyTest.kt`.
- Executed here: a standalone JVM simulation of the entry-reading/budget algorithm against the three new scenarios (oversized ignored entry → scanned=1; oversized source entry → scanned=1 and entry reported skipped; total budget overflow → scan stops, scanned=0). All three matched expectations.
- **Not executed here:** Kotlin compilation and the official `:app:testDebugUnitTest` Gradle run (no Kotlin compiler or network in this environment). These must be verified in CI before release.
