# SiteGuard Android v0.8.0 — Domain Module Map

## Runtime core modules

- **Authorization.kt / WebsiteSecuritySpecialistEngineV2.kt** — exact host/path/port/time/test class/request budget, engagement validation and website-specialist coverage.
- **WebsiteDiscoveryEngineV1.kt** — bounded passive crawler, per-link scope re-check, DNS resolution plus IP pinning, TLS hostname verification, no credentials/forms/cookies/query strings, redirects not followed.
- **GraphQlSoapSchemaAnalyzer.kt / ApiSchemaAnalyzer.kt** — static GraphQL SDL, SOAP WSDL and OpenAPI JSON/YAML schema checks.
- **ProjectArchiveAnalyzer.kt / SourceCodeAnalyzer.kt / WordPressSecurityAnalyzer.kt** — source and archive review, dependency inventory, WordPress/WooCommerce heuristic findings and APK/AAB archive marker inventory.
- **SpecificationCoverageRegistryV080.kt / ExecutionOrderAcceptance.kt** — runtime 00–23 status register; reports and dashboard disclose partial/remaining status.
- **PersistentChainOfCustodyLedgerV1.kt / ThreatForensicsEngine.kt / EvidenceSanitizer.kt** — local hash-linked custody events, evidence hashes and redaction.
- **AttackGraphRiskEngine.kt / RiskEngine.kt / RemediationPatchEngine.kt / WebsiteRemediationPlaybook.kt** — evidence graph, risk ranking, remediation recipes, patch preview and developer tickets.
- **LocalSecurityKnowledgeStore.kt / LocalSecurityKnowledgePack.kt / SecurityKnowledgeBase.kt** — local reference data and offline query.
- **NetworkEnterpriseSecurityAnalyzer.kt / CloudConfigurationAnalyzer.kt / MobileSecurityAnalyzer.kt / DefensiveIntelligence.kt / LabSimulation.kt / SecurityAutomation.kt** — restricted network checks, static config analysis, mobile/defensive analysis and bounded local jobs/scenarios.

## UI integration

- Existing Compose dark/red palette, dashboard, card style and four-item bottom navigation preserved.
- Website passive discovery is an opt-in checkbox on the scan view.
- Project ZIP analysis records read-only acquisition and completion events in the local custody ledger.
- Existing finding cards link to remediation plan/ticket preview.
- A specification coverage card shows documents 00–23 and avoids claiming that the whole prompt pack is complete.
- JSON and HTML exports include 00–23 statuses and remaining work.

## Boundaries

The modules are not full integrations with all named services/tools. Provider-specific IAM/AD/Entra, full authenticated DAST, full AST/taint, live WordPress runtime, MobSF, full forensic formats, signed feed ingestion, Android APK build/device validation, PDF, Linux worker and isolated VM/container lab are not complete. See `SPECIFICATION_GAPS.md` and `IMPLEMENTATION_MATRIX_00_23.md`.
