# SBOM Status — SiteGuard Android v0.8.0

- Declared Android/Compose/Kotlin dependencies are listed in `sbom/app-declared-dependencies.cdx.json`.
- The CI workflow resolves the release runtime dependency graph and uploads `resolved-dependencies.txt` when it runs successfully.
- Full resolved CycloneDX SBOM, transitive license review, dependency vulnerability matching and reproducible build provenance require a successful Gradle CI run.
- Source-level SBOM output for analyzed projects remains best-effort and is not the same as the app's own complete dependency SBOM.
- No third-party scanner binaries or toolchains were added in this release.


## v0.8.0 dependency changes
No third-party library was added for the v0.8.0 modules. GraphQL SDL and OpenAPI YAML are reviewed by bounded first-party deterministic parsers; WSDL uses the platform XML parser with DTD/external entities disabled; the custody ledger uses platform SHA-256/Base64; crawler uses platform networking APIs. The resolved Gradle dependency graph has not been generated in this environment because Gradle/Android SDK were unavailable. The CI workflow exports `releaseRuntimeClasspath` after a successful build.

## v0.14.0 supply-chain status

- No new third-party Android runtime library was added for the v0.14.0 advanced modules; JSON parsing, bounded HTTP adapters and binary inspection use platform/JDK code. Existing AndroidX WorkManager 2.12.0 and existing Compose/AndroidX dependencies are reused.
- `sbom/app-declared-dependencies.cdx.json` remains the declared dependency snapshot; it is not a fresh, complete resolved SBOM for v0.14.0.
- The CI workflow is configured to export `releaseRuntimeClasspath` to `resolved-dependencies.txt` after a successful Gradle build. That workflow has not yet run, so the resolved dependency graph has not been verified.
- No full CycloneDX runtime SBOM, dependency vulnerability report, license-policy report, reproducible-build attestation or provenance statement is claimed.
- GitHub Actions are referenced by major version tags rather than immutable full commit SHAs. Pinning and scheduled dependency review remain release-hardening tasks.
- Signing keys are not bundled. CI signing is conditional on four owner-managed GitHub Secrets.

