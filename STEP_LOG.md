# Step Log — incremental hardening on top of v0.8.0

The app version stays `0.8.0` / `versionCode 9` while these steps are applied, because `tools/final-release-gate.sh`
pins that value. A version bump is planned only after the last step.

## Step 1 — TLS handshake/certificate failures become findings  ✅ DONE

**Problem.** `ScanEngine` and the passive crawler swallowed `SSLHandshakeException`/`CertificateException`.
An expired certificate, a hostname mismatch or an untrusted chain produced only an anonymous "connection failed"
message with `findings = []`, so the most important TLS observation was never reported. The specialist coverage
then also reported `WEB-TLS-EDGE` as `NOT_TESTED`.

**Changes.**
- New `core/TlsFailureClassifier.kt`: walks the exception cause chain (cycle-safe, depth-limited) and classifies into
  `CERTIFICATE_EXPIRED`, `CERTIFICATE_NOT_YET_VALID`, `CERTIFICATE_REVOKED`, `WEAK_ALGORITHM`, `HOSTNAME_MISMATCH`,
  `UNTRUSTED_CHAIN`, `NON_TLS_ENDPOINT`, `HANDSHAKE_REJECTED`. Plain network problems (timeouts, resets, refused,
  peer closed, EOF) return `null` and are deliberately **not** reported as TLS findings.
- `ScanEngine.scan`: on an HTTPS target, a classified failure returns a `Finding` (`SG-TLS-VALIDATION-*`) with sanitized,
  single-line evidence, the pinned IP and honest coverage notes.
- `WebsiteDiscoveryEngineV1`: classified failures are recorded as a `TLS_VALIDATION_FAILED` event; other failures keep
  `REQUEST_FAILED` and their message is now passed through `EvidenceSanitizer`.
- `WebsiteSecuritySpecialistEngineV2.assessPassiveWebScan`: `WEB-TLS-EDGE` is `NEEDS_MANUAL_REVIEW` (not `NOT_TESTED`)
  when a TLS validation finding exists; `WEB-HEADERS-COOKIE` stays `NOT_TESTED` because no HTTP response was obtained.

**Honesty rules kept.** Findings are `PROBABLE` (certificate kinds) or `UNVERIFIED` (non-TLS endpoint, generic
handshake rejection), never `CONFIRMED`: the observation is from this device's trust store and a wrong device clock,
a proxy/VPN or a custom CA can produce the same exception. Every finding says so and tells the owner how to verify.

**Verification performed.**
- 13 new JUnit tests (`TlsFailureClassifierTest`) — all PASS in a local Kotlin runner (see `TEST_RESULTS_step1.txt`).
- 31 pre-existing tests still PASS in the same runner.
- Real TLS servers (generated CA + leaf certificates) on loopback: valid → normal scan with no TLS-validation finding;
  expired → `SG-TLS-VALIDATION-EXPIRED`; wrong SAN → `SG-TLS-VALIDATION-HOSTNAME`; unknown CA →
  `SG-TLS-VALIDATION-UNTRUSTED-CHAIN`.

**Not verified.**
- Exception messages were exercised on the desktop JVM (JSSE). Android's Conscrypt words some errors differently;
  the classifier covers the known Conscrypt phrases (e.g. `WRONG_VERSION_NUMBER`, `Trust anchor ... not found`,
  `Hostname ... not verified`) but this was not run on a device.
- No Gradle/Android build, lint or device test was run (no Android SDK here).
- The existing `SpecialistArchiveIntegrationTest` could not run in the local runner because it needs the real
  `org.json` parser; it fails identically on the untouched v0.8.0 source in this runner (environment limit, not a regression).

## Steps 2–7 — applied together, NOT compiled  ⚠️

None of these changes were compiled or run: this environment has no Kotlin compiler, Gradle or Android SDK.
Only the AddressPolicy range table was cross-checked with an independent Python replica (0 mismatches on the test vectors).
Run `:app:testDebugUnitTest` before trusting any of it.

- **Step 2 (crawler):** `Transfer-Encoding: chunked` decoding; single bracket pair in `Host` for IPv6; bare host for DNS/SNI/TLS;
  up to 3 validated IPs tried if connect fails. Tests: `CrawlerRobustnessTest`.
- **Step 3 (AddressPolicy):** exact IPv4 special-use blocks (no more over-blocking 192.0.x.x / 198.51.x.x); IPv6 NAT64 and 6to4 judged by
  the embedded IPv4, Teredo/2001::/23/ORCHID/SRv6/discard/doc ranges non-public. Tests: `AddressPolicyTest`.
- **Step 4 (ownership + policy):** `OwnershipProofV1` (well-known token over validated HTTPS, no redirects, constant-time match,
  upgrades manifest to TECHNICAL_OWNERSHIP only on VERIFIED); `ScanPolicyBridgeV1` routes `ScanEngine` through `SecurityPolicyEngineV1`.
  Tests: `OwnershipProofTest`. **Not done:** UI screen for the challenge; DNS TXT proof (no TXT API on plain Android, needs DoH).
  Note: the bridge's IP range is built from the DNS answer, so it enforces host/port/class/time/private-IP rules, not an owner-supplied CIDR list.
- **Step 5 (app hardening):** `usesCleartextTraffic=false` + `network_security_config.xml`; `res/` (theme, colors, strings, adaptive icon);
  R8 + resource shrinking + `proguard-rules.pro`; optional env/gradle-property signing config. Note: the scanner uses raw sockets,
  which Network Security Config does not govern; it protects all other connections.
- **Step 6 (CI):** sign → checksum → single upload (unsigned release APK and keystore deleted before upload); release gate runs in CI;
  wrapper validation when present; `tools/bootstrap-wrapper.sh` generates the binary wrapper files. **Not done:** wrapper jar itself
  (binary), action SHA pinning (needs verification against each action repo; marked TODO in the workflow).
- **Step 7 (scanner depth):** `PassiveHygieneChecksV1`: HTTP→HTTPS redirect classification (findings PROBABLE/INFORMATIONAL, never CONFIRMED),
  robots.txt and sitemap parsing (regex, no XML parser). Tests: `PassiveHygieneChecksTest`. **Not done:** DNS records (SPF/DMARC/CAA),
  UI/report integration of the new checks, wiring into specialist coverage.

## Step 8 — UI for ownership proof and hygiene checks  ⚠️ not compiled

New `OwnershipHygienePanel.kt` (one composable, own colors) inserted once in the scan card of `MainActivity.kt`:
create a token challenge, verify it over HTTPS, then run HTTP→HTTPS / robots.txt / sitemap checks (max 3 GET). Buttons require the
existing "I own / am authorized" checkbox. Results are shown in the panel and the findings are also merged (de-duplicated by id) into the main `findings` list, so the
findings tab and the JSON/HTML export include them. They are **not yet** in the specialist coverage matrix, and events/limitations
are shown only in the panel.

## Remaining

- Commit Gradle wrapper, run the real build/tests/lint, fix any compile errors in MainActivity and the new code.
- Add hygiene events/limitations and ownership status to the report and coverage matrix; full engagement-intake form.
- DNS records via DoH (or a resolver library), TLS protocol/cipher enumeration, certificate detail, split MainActivity.kt.
