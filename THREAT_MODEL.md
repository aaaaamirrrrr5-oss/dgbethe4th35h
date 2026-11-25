# Threat Model — SiteGuard Android v0.8.0

## Assets

- Authorization/engagement manifests, scope data and expiry.
- Local source archives, WordPress configuration/code, dependency manifests and finding evidence.
- Local database, reports, forensic hashes, audit history and optional patch previews.
- Android app integrity, signing material held outside repository, and user-selected files.

## Trust boundaries

1. User/device ↔ Android UI.
2. UI ↔ domain services and scanner adapters.
3. App ↔ external website over a tightly scoped request.
4. Imported ZIP/source/config ↔ parser and static analyzers.
5. Evidence records ↔ local reporting/export.
6. Optional public security feed ↔ local knowledge staging data.
7. GitHub CI ↔ unsigned/signed build artifacts.

## Main threats and controls

- Scope escape: exact allowlist and path/port/time/method checks; discovered redirects/hosts do not inherit permission; existing HTTP scanner does not follow redirects and pins the chosen DNS address for its single request.
- DNS rebinding/SSRF: validate resolved address; block loopback/private/link-local/reserved ranges unless explicitly approved; no arbitrary URL fetch or internal probing. The v2 website manifest includes explicit host/path and IP-range metadata but full resolved-IP range enforcement is not yet wired through every adapter.
- Malicious ZIP/archive: in-memory bounded parsing, path traversal rejection, compressed/expanded size and entry caps; no disk extraction or code execution.
- False positive/unsupported claims: findings carry confidence/status/evidence; probable heuristics become manual review; missing controls remain Not Tested/Unsupported; no Pass from empty findings.
- Data leakage: credential/PII redaction at evidence collection; local-only report export on explicit user action; do not log secrets.
- Dangerous remediation: plan/diff only; require exact unique snippet, safe path and approval lifecycle; no automatic production apply.
- Commerce impact: no real order/payment/customer/refund/inventory mutation; use synthetic accounts and gateway sandbox for tests.
- Supply chain: no blind tool download/execution; CI artifacts and SHA256; user keystore kept in GitHub Secrets.
- AI/privacy: no hosted AI inference/API endpoint or mandatory server.

## Residual risks

The source analyzers are not full AST/taint systems. Runtime WordPress, authenticated API, payment/webhook, identity/cloud and binary mobile testing need dedicated read-only integrations, staging/lab fixtures and explicit authorization. The Android app may be suspended; scheduled jobs are not always-on. Android SDK/Gradle build, lint, APK install/upgrade and hardware resource tests remain pending CI/device execution.


## v0.8.0 additional controls
- Website crawler rejects query-bearing entry URLs, never sends cookies/credentials/forms, does not follow redirects/external links, checks all resolved addresses and pins a socket to one checked IP.
- CIDR parser accepts numeric IPv4/IPv6 literals only; it never treats a hostname as a network address.
- `Set-Cookie` is excluded from persisted crawler evidence. Response body is capped and stored only as a digest plus sanitized title/allowlisted headers.
- Local hash-linked evidence ledger detects edits to recorded events, but is not a hardware-backed or external signature and cannot independently prove that the ledger file itself was not replaced wholesale.

## v0.14.0 advanced module trust boundaries and residual risks

- **Local reasoning:** deterministic heuristics prioritize records and explain evidence links; it is not a generative model, is not trained in-app, and can miss unknown vulnerability classes.
- **Threat feeds:** CISA KEV is fetched over HTTPS and bounded/schema/date/CVE/count validated; OSV queries use a fixed HTTPS endpoint. Transport validation is not independent publisher-signature verification. Feed content is untrusted input and must not become executable instructions.
- **WordPress/WooCommerce:** the new runtime adapter only issues read-only REST GET requests after explicit user consent. Application Passwords are transient in UI memory and must not be persisted. It does not mutate products/orders/payments or inspect the database. DNS results are validated before the request but not pinned at socket connect; a DNS-rebinding race is a residual limitation.
- **Web/API:** the new surface analyzer is bounded to same-origin GET paths and response metadata. It does not crawl arbitrary discovered links, authenticate, fuzz, exploit, or test business logic. The new adapter validates resolved addresses before the request but does not pin the socket; the older passive scanner retains its own IP-pinning behavior.
- **AST/Taint:** lexical/statement and selected source-to-sink analysis is an approximation; no compiler-grade AST, type resolution, full CFG, alias tracking or interprocedural analysis is provided. Treat findings as leads requiring review.
- **Cloud/Network:** newly added checks review selected local IaC/config files; they do not connect to cloud accounts, enumerate effective IAM, or prove runtime exposure.
- **APK:** ZIP/AXML/DEX processing is bounded and rejects traversal; this is not a full reverse-engineering sandbox. APK v2/v3/v4 signature verification, bytecode decompilation, native disassembly and dynamic execution are not implemented.
- **Remediation:** changes are limited to a user-selected local workspace, with exact-match and hash checks, backups and guarded rollback. No remote site, database or cloud production change is performed.
- **Automation:** periodic jobs are deferrable WorkManager operations, not an always-on monitor. Site credentials and file grants are not persisted for unattended use.
- **CI and signing:** signing keys are external GitHub Secrets and are not packaged. Current GitHub Actions references use version tags, not immutable full commit SHAs; workflow execution and supply-chain provenance have not yet been verified.

