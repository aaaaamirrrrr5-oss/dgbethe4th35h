# Architecture — SiteGuard Android 0.8.0

## Intent

Android-first, local-first, deterministic security assessment. The original dark red/black Compose dashboard and four-item bottom navigation are retained. The product has no hosted AI inference, no AI API key and no mandatory backend/server. Internet access is limited to user-initiated authorized assessment or optional public-data update work; no target content is sent to an AI service.

## Layers

| Layer | Source modules | Current boundary |
|---|---|---|
| Presentation | `MainActivity.kt` | Existing dashboard/cards/navigation retained. New coverage card, passive discovery opt-in, specialist report details and local evidence-ledger actions use existing styling. Not every domain has a dedicated screen. |
| Core contracts | `PlatformContracts.kt` | Versioned scanner/evidence/knowledge/remediation/report contracts. |
| Authorization | `Authorization.kt`, `SecurityPolicyEngine.kt`, `WebsiteSecuritySpecialistEngineV2.kt`, `WebsiteDiscoveryEngineV1.kt` | Exact host/path/port/time/test-class/request budgets. Website crawler adds numeric CIDR validation and resolved-IP pinning. Not every adapter uses one common scope-token/egress layer yet. |
| Orchestration | `ScanOrchestrator.kt`, `DeviceCapabilityDetector.kt`, `SecurityAutomation.kt` | Bounded in-process jobs, cancellation and resource checks. Durable WorkManager recovery is not implemented. |
| Assessment engines | `ScanEngine.kt`, `SourceCodeAnalyzer.kt`, `ProjectArchiveAnalyzer.kt`, `ApiSchemaAnalyzer.kt`, `GraphQlSoapSchemaAnalyzer.kt`, `WordPressSecurityAnalyzer.kt`, `MobileSecurityAnalyzer.kt`, `NetworkEnterpriseSecurityAnalyzer.kt`, `CloudConfigurationAnalyzer.kt`, `WebsiteSecuritySpecialist.kt` | Static/rule-based source and configuration review plus narrow passive network checks. No complete AST/taint, authenticated DAST, cloud provider or runtime WordPress integration. |
| Website discovery | `WebsiteDiscoveryEngineV1.kt` | GET-only crawler with per-URL scope re-check, checked-DNS IP pin, TLS hostname validation, no cookies/credentials/forms, query string blocked, redirects/external links not followed, body cap and hash-only body evidence. |
| Tool ecosystem | `GitHubToolIntelligence.kt` | Tool metadata/provenance/license review model; no blind repo execution, auto-download or binary install. |
| Graph and risk | `AttackGraphRiskEngine.kt`, `DefensiveIntelligence.kt`, `RiskEngine.kt` | Evidence-linked nodes and observed/inferred distinction. Cross-domain persistent graph and calibrated live path data remain incomplete. |
| Remediation | `RemediationPatchEngine.kt`, `WebsiteRemediationPlaybook.kt` | Fourteen website playbook recipes, reviewable plan/ticket and safe snippet preview. No automatic writes, PR or production deployment. |
| Threat/forensics | `ThreatForensicsEngine.kt`, `PersistentChainOfCustodyLedgerV1.kt`, `EvidenceSanitizer.kt` | Hash/timeline metadata, redaction and local append-only hash-linked custody ledger. Not a hardware-backed signature or external witness. |
| Lab | `LabSimulation.kt` | Local deterministic synthetic fixtures; not a VM/container orchestrator. |
| Knowledge | `SecurityKnowledgeBase.kt`, `LocalSecurityKnowledgePack.kt`, `LocalSecurityKnowledgeStore.kt` | Curated local SQLite/FTS data; no signed live feed or full CVE/OSV dataset. |
| Coverage registry | `SpecificationCoverageRegistryV080.kt`, `ExecutionOrderAcceptance.kt` | Runtime mapping of every source spec 00–23 to status, verified checks and outstanding work; all complete documents remain partially supported. |
| Reporting/QA | `ReportingQualityEngine.kt`, `JsonReportExporter.kt`, `LocalAuditHistory.kt` | JSON/HTML, specialist coverage, per-spec coverage and export metadata. No PDF exporter or full resolved SBOM yet. |
| Release | `.github/workflows/android-ci.yml`, `BuildReleasePolicy.kt`, `tools/` | Workflow provisions Gradle/Android SDK in CI. The actual CI workflow and APK/device release test still need to run in the user's repository. |

## Scope flow

1. User explicitly declares ownership/authorization for a precise asset.
2. The UI scanner creates a short-lived, exact host/port/path authorization record.
3. Each request checks expiry, method/test class, request budget, host, path and port.
4. The passive crawler resolves the authorized hostname, rejects any resolved answer outside its numeric CIDR/public-address policy and pins the socket to one checked IP; HTTPS performs hostname verification and SNI.
5. Query-string entry URLs are blocked to avoid sending or retaining token-bearing parameters. The crawler never sends cookies, tokens, login data or forms; redirects and external links are not followed.
6. Explicit TCP probe uses exact numeric IP and port; no range sweep or banner grabbing.
7. Other provider adapters are still being migrated toward a shared end-to-end egress and scope-token model.

## Data / privacy boundaries

- Source/ZIP analysis is local; ZIP members are not extracted to disk by the archive analyzer.
- Web scan history is encrypted at rest with AES-GCM/Android Keystore and capped at 30 reports.
- The custody ledger is a local hash-linked append-only API that detects altered events, but does not prevent wholesale file replacement or provide independent signing.
- `Set-Cookie` is excluded from crawler evidence. Bodies are capped and not persisted; only hashes and sanitized metadata are retained.
- Android backup is disabled; complete backup/restore is not implemented.
- No API key, hosted AI endpoint or mandatory server credential is embedded.

## Execution and recovery

Website scans are foreground/cooperative. Jobs are bounded and cancellation-aware but there is no guarantee of always-on monitoring, exact cancellation of arbitrary blocking code, or process-death recovery. Device thermal/battery/resource and Android API/ABI tests remain required.

## Remaining architecture work

Durable WorkManager queue and migrations, authenticated local IPC, optional isolated local Linux worker, universal egress enforcement across adapters, signed knowledge updates, full DAST/mobile/cloud/identity/runtime adapters, APK binary parsing/signature verification, PDF export, complete backup/restore and real Android build/install/release verification.
