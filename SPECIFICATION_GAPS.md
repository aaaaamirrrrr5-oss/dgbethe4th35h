# Specification Gaps — SiteGuard Android v0.8.0

## Newly implemented in v0.8.0

- Static schema analysis now includes GraphQL SDL, SOAP WSDL using an XML parser with DTD/external entity access disabled, and line-oriented OpenAPI YAML. This is schema review only; no endpoint authentication or runtime authorization is exercised.
- A bounded passive website discovery engine can crawl up to a configured page/depth/body budget using GET only. It re-checks host/path/port/time/test-class/request budget for each URL, resolves DNS once per request, checks all returned IPs against policy, pins the socket to a previously checked address, validates TLS hostname, does not follow redirects or external links, and does not submit forms or credentials.
- The crawler rejects an initial URL containing a query string before any network request and excludes `Set-Cookie` from retained response headers. Raw response bodies are not persisted; only bounded metadata, title, response-header allowlist and SHA-256 body hash are retained.
- CIDR validation is numeric-literal only for IPv4/IPv6; hostnames such as `localhost` are not accepted as CIDR networks. Private/reserved address connection requires an explicit matching numeric range in the website engagement manifest.
- A local append-only hash-linked chain-of-custody ledger records acquisition and analysis events and detects altered records. It is local SHA-256 integrity chaining, not a hardware-backed signature or independent external witness.
- WordPress source checks include additional AJAX nonce/capability, unsafe deserialization, WooCommerce object ownership, file editor and redacted secret-constant observations. These remain source heuristics and require human review.
- APK/AAB archive inspection records binary AndroidManifest/DEX presence as inventory metadata; it does not decode binary AXML, inspect DEX semantics or verify APK signatures.
- A 00–23 runtime specification registry is shown in the existing dashboard and exported in JSON/HTML. It deliberately labels every whole specification as partially supported rather than claiming that the presence of a module makes an entire specification complete.

## Website Security Specialist v2 / Remediation Playbook

Still partial or blocked:

- The existing UI does not yet provide the complete engagement-intake form for client ID, written proof attachments, third-party provider exclusions, synthetic identity roster, exact CIDR list and contact/timezone details. The legacy screen still creates a narrow single-host user-declaration manifest for the passive scan.
- The crawler resolves A/AAAA addresses through the platform resolver as part of connection pinning, but does not enumerate MX/TXT/CAA/NS records. It does not yet read `robots.txt` or parse sitemap indexes. Full architecture discovery, CDN/WAF origin analysis and broad endpoint inventory are not implemented.
- IP/CIDR enforcement is integrated into the new website crawler, but it is not yet a universal shared egress gate across every network/tool adapter.
- Website architecture from ZIPs is source-evidence based. It does not establish runtime deployment topology, CDN routing, active plugins, active themes, user/role state, multisite boundaries or production configuration.
- PHP/JS/TS and other language analysis remains heuristic/signature based; full AST, interprocedural data flow and taint tracking are not present.
- WordPress/WooCommerce runtime inspection requires a dedicated authenticated read-only integration and a disposable staging/sandbox site. No live customer/order/payment/inventory data is accessed or modified.
- API tests are mostly schema/static or passive checks. BOLA/BFLA with synthetic accounts, JWT/JWS runtime validation, GraphQL depth/complexity, SOAP operations, webhook replay and business logic remain untested/unsupported in this release.
- The 14 remediation playbook patterns generate reviewable plans and developer tickets. The app does not autonomously modify production code, database, orders, payment settings or configuration; backup/staging/rollback execution remains owner-operated.

## Other domains

- Cloud/IAM/Kubernetes and enterprise identity are static configuration review only; no cloud account, Entra, Active Directory or Kerberos live connector is supplied.
- Red-team output is defensive mapping and synthetic simulation; no real lateral movement, stealth, credential attack or compromise workflow is supported.
- GitHub tool intelligence has a registry/review model; automatic untrusted repository execution, live provenance verification and signed modular installer remain incomplete.
- Knowledge base is local and useful offline, but the shipped curated dataset is not a complete/current CVE/NVD/CISA/OSV/vendor feed. Signed update manifests and trusted bundle rollback need implementation.
- Network checks are deliberately narrow (exact IP/port/TLS); full range discovery, fingerprinting and enterprise segmentation analysis are not complete.
- Mobile analysis does not yet decode binary AXML, verify APK/AAB signatures, run MobSF or execute APKs in an isolated analyzer.
- Forensics supports file hashing, metadata/timeline foundations and a local hash-linked ledger; broad forensic file formats, signed evidence export and external witness are missing.
- WorkManager durable one-time scheduling and recovery were added in v0.13.0; exact real-time execution, always-on monitoring and notification/foreground-service lifecycle are not guaranteed.
- Lab scenarios are synthetic and local; there is no disposable VM/container orchestrator.
- JSON/HTML reports are supported. (PDF export was added in v0.13.0; see the v0.13.0 update below.)
- Optional local Linux worker, sandboxed tool downloads, authenticated IPC and full toolchain isolation are not implemented.

## Android/release blockers

- The environment used for this package has no Android SDK/Gradle executable. The entire Kotlin `core` source set was compiled with the local Kotlin compiler using compatibility stubs; this does not compile `MainActivity` against real Compose/Android artifacts and is not a Gradle build.
- `:app:testDebugUnitTest`, `:app:lintDebug`, `:app:assembleDebug`, `:app:assembleRelease`, APK signing, install/upgrade/restore and physical-device/ABI tests have not been executed.
- GitHub Actions is included but has not been run in the user's repository. A release keystore is not bundled and must remain user-controlled.

## Step 1 update (TLS handshake/certificate failures)

- Certificate/handshake validation failures on the passive web scan are now reported as `SG-TLS-VALIDATION-*` findings
  (PROBABLE/UNVERIFIED, never CONFIRMED) instead of an anonymous connection failure. See `STEP_LOG.md`.
- Still missing for TLS: server-supported protocol versions and cipher enumeration, certificate detail extraction
  (issuer, SAN list, expiry date) when validation succeeds, OCSP/CT checks, and redirect-aware HTTP→HTTPS verification.
- Exception wording was tested on the desktop JVM only; Android Conscrypt wording is handled by documented phrases but not device-tested.

## Steps 2–7 update

See `STEP_LOG.md` and `TEST_RESULTS_steps2_7.txt`. All code from these steps is uncompiled and untested in a real Gradle/JUnit run.
Still missing: DNS record checks, DNS TXT ownership proof, UI for ownership/hygiene results, committed Gradle wrapper, action SHA pinning.

## v0.11.0 update

- Added: TLS session/leaf-certificate observation after a successful handshake, JSON schema 5 `passive_hygiene` section.
- Still missing: supported protocol/cipher enumeration, intermediate chain/OCSP/CT checks, DNS records (SPF/DMARC/CAA) and DNS TXT ownership proof,
  committed Gradle wrapper, action SHA pinning, and any real compile/JUnit/device run of steps 2–9 and v0.11.0 code.

## v0.12.0 update

- Added: security.txt (RFC 9116) and present-HSTS-header evaluation in the passive hygiene checks; JSON schema 6.
- Still missing: PGP signature check, link reachability, enumeration of protocol/cipher support, chain/OCSP/CT, DNS records, DNS TXT ownership proof,
  committed Gradle wrapper, action SHA pinning, and any real compile/JUnit/device run.

## Honest status semantics

`Implemented` means a feature exists in source. `Tested` means the exact named test was executed and passed. A smoke test does not certify a full specification. Empty findings are not a PASS, unsupported controls are not silently treated as secure, and no AI API or mandatory hosted backend is used.

## v0.9.0 — UX and unified findings update

- The original dark/red visual language and four bottom-navigation destinations remain intact; the header, activity state, card hierarchy, metrics and navigation contrast were refined.
- Website, source-file and ZIP-project findings are now deduplicated, ordered by severity and displayed in one shared results list. JSON top-level `findings` uses the same unified collection; source-specific blocks remain available for traceability.
- Deep Website Security Specialist controls, evidence, architecture edges, test plans, defensive mappings and dependency rows are collapsed by default and remain available through an explicit expand action.
- Empty state distinguishes “no assessment run” from “assessments ran with no findings”; neither state is described as proof of security.
- Version advanced to 0.9.0 / versionCode 10. JSON report schema advanced to version 3.
- `docs/PROMPT_40_DOMAIN_COVERAGE_v0.9.0.md` maps all 40 domains from the uploaded 100,000-line prompt to real source paths, tests and remaining limitations. No complete domain is certified as fully implemented or fully tested.
- These Compose/UI changes are source-edited but require a real Android Gradle/SDK build and device review. This environment does not contain Gradle, Android SDK, adb or a committed Gradle wrapper JAR; Android UI compilation and APK creation remain unverified.


## v0.10.0 — Authorization, evidence and cancellation hardening

- Authorization manifest validation now fails closed for malformed host/path/port/time/budget data; URL path validation rejects dot segments, encoded separators/dots, controls, malformed escapes and double-decoding `%25`. Path-prefix checks are segment-aware. Numeric IPv4 values must use four unambiguous octets; IDN names are canonicalized.
- Evidence redaction now covers JSON quoted secrets, ordinary credential assignments, Authorization Bearer/Basic, PEM private keys, GitHub/AWS tokens, JWT and credential-bearing URLs. JSON finding/remediation report fields including root-cause hypothesis and proposed patch diff are scrubbed before export.
- Scan and discovery workflows have coroutine deadlines and propagate cancellation rather than classifying it as a network failure. The platform DNS call `InetAddress.getAllByName` remains a blocking native resolver operation and may not be interruptible immediately on all devices.
- New JUnit test source files exist for authorization-scope and evidence-redaction regression. They have not been run via Gradle in this environment.
- These changes improve but do not complete domains 01/04/05/06/08/10/28/40. Aggregate coverage remains 38 Partial, 1 Unsupported and 1 Blocked; no whole domain is certified complete.


## v0.13.0 update — delivered improvements and remaining gaps

Delivered in source:
- Passive DNS posture for SPF/DMARC/CAA via Google Public DNS-over-HTTPS.
- Android Keystore/AES-GCM encrypted archive for web/source/project/DNS reports.
- Persistent bounded automation queue with interrupted-task recovery, pre-claim authorization revalidation and user-triggered foreground execution.
- Encrypted per-asset drift baselines and evidence-quality scoring.
- Multi-page RTL PDF report export.

Still not complete or device-verified:
- WorkManager deferrable background execution was added in v0.13.0. Exact real-time scheduling, always-on service and notification/foreground-service lifecycle remain unsupported.
- Independent page-level navigation (the existing bottom bar still scrolls to sections in one long list), full accessibility review and cross-device battery/performance validation.
- Authenticated WordPress REST API integration and live WooCommerce runtime inspection.
- Full AST/data-flow/taint analysis, full DNS-zone/SPF recursive validation, certificate transparency/OCSP/revocation depth.
- Cloud provider/identity/Active Directory runtime connectors, isolated Linux worker, deep APK/AAB binary analysis.
- Full Android Gradle build, JUnit, lint, signing, install/upgrade and physical-device tests for v0.13.0.
- Committed Gradle Wrapper and full-SHA pinning of all GitHub Actions.

DNS note: queried domain names are sent to Google Public DNS-over-HTTPS. The user interface and release notes disclose this external resolver behavior.

## v0.14.0 — implementation state and remaining blockers

Delivered in source (see `IMPLEMENTATION_MATRIX_v0.14.0.md`): local evidence reasoning; CISA KEV and OSV query adapters; explicit-consent read-only WordPress/WooCommerce REST checks; bounded Passive web/API surface analysis; lexical AST/Taint approximation; static IaC/Cloud posture; bounded APK ZIP/AXML/DEX analysis; local guarded patch/rollback; Advanced Hub; daily CISA WorkManager refresh; encrypted comparative reports and CI APK/AAB pipeline.

Actual local validation: 12/12 standalone JVM smoke tests passed and source release-gate checks were run. These do not test Compose, Android resources, Gradle plugins, JUnit runtime, R8, signing, installation or physical devices.

Still missing or partial:
- Local reasoning is deterministic rule-based decision support, not a trained local LLM or general autonomous agent.
- Threat-intelligence transport is HTTPS plus schema validation, without a separately verified signed-feed chain or automated full NVD/GHSA/EPSS sync. Live feed access has not been verified here.
- WordPress checks depend on REST being available and credentials/capabilities; deep user-role/capability matrix, multisite, database, plugin runtime instrumentation, payment sandbox and write-path validation are not implemented. DNS is not pinned at socket connect in the new adapter.
- Website/API tests are bounded same-origin GET and metadata checks, not authenticated DAST, BOLA/BFLA, GraphQL runtime, webhook replay, rate-limit load testing or business logic. The WordPress and web-surface adapters now use `PinnedHttpsClientV1` by default (single DNS resolution, validated-address pinning, TLS verified before any header/credential is written, no redirects); this path has JVM-level parsing/validation tests but has not been exercised against a live TLS server on a device.
- AST/Taint is lexical, not compiler-grade; no complete CFG, types, aliasing or interprocedural analysis.
- Cloud checks are static IaC/config analysis, not live AWS/Azure/GCP identity, asset or runtime posture.
- APK parser does not verify v2/v3/v4 signatures, decompile DEX, disassemble native code, inspect complete AAB/splits or run a dynamic sandbox.
- Remediation does not make remote/production changes; local workspace symlink/concurrency/crash-recovery hardening needs further adversarial tests.
- Automation schedules CISA and retains the prior passive-web queue; other source/WP tasks remain user-driven. WorkManager is deferrable and not continuous monitoring.
- Gradle Wrapper scripts/JAR are absent; CI provisions Gradle 8.9. GitHub Actions are tag-referenced, not pinned to immutable SHAs. No lockfile/dependency verification metadata or full SBOM has been generated yet.
- JUnit, Gradle build, Compose compilation, lint, APK/AAB generation/signing and device tests remain unexecuted in this environment.


## v0.14.0 post-release update (archive, scan engine, workers, build)

- Fixed/added after the v0.14.0 package: per-entry ZIP size cap no longer aborts the whole scan (total expanded budget still does); directory and duplicate ZIP entries handled; scan engine uses ASCII/punycode host and percent-encoded non-ASCII request targets and falls back across up to 3 validated resolved addresses; an OS-interrupted background assessment is re-queued within its retry budget; `.env` secret detection added; `gradlew`/`gradlew.bat` bootstrap stubs and a self-contained `tools/bootstrap-wrapper.sh`. Details: `RELEASE_NOTES_v0.14.0.md`.
- **Still not done in this package:** no Kotlin compile, `:app:testDebugUnitTest`, lint, APK/AAB build or device test has been executed for any of the above (no compiler/network in the authoring environment); the official Gradle wrapper JAR is generated on first `./gradlew` run; GitHub Actions are not SHA-pinned; the engine still does not read `robots.txt`/sitemaps, enumerate TLS protocols/ciphers, or check OCSP/CT; AST/taint analysis, runtime WordPress inspection, APK signature verification and binary AXML decoding in the ZIP analyzer remain unimplemented as listed above.
