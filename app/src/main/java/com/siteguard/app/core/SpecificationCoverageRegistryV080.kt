package com.siteguard.app.core

/**
 * Runtime capability register for the complete NEXUS prompt pack (00–23).
 * A prompt being present in docs/specifications does not mean its entire feature set is live.
 */
data class SpecificationCoverageItemV080(
    val number: Int,
    val fileName: String,
    val title: String,
    val status: SpecificationImplementationStatus,
    val implementedAreas: List<String>,
    val verifiedChecks: List<String>,
    val remainingWork: List<String>
)

data class SpecificationCoverageSummaryV080(
    val expectedDocuments: Int,
    val presentDocuments: Int,
    val testedWholeDocuments: Int,
    val implementedWholeDocuments: Int,
    val partiallySupportedDocuments: Int,
    val unsupportedDocuments: Int,
    val sequenceValid: Boolean,
    val items: List<SpecificationCoverageItemV080>
)

object SpecificationCoverageRegistryV080 {
    private val entries = listOf(
        item(0, "00_MASTER_EXECUTION_PROMPT.txt", "Master execution and release rules", listOf("local-first/no AI API policy", "authorization-first constraints", "finding quality and evidence contract"), listOf("Core Kotlin source compilation", "scope and archive regression checks"), listOf("Full end-to-end product acceptance on Android device", "signed production release and full domain coverage")),
        item(1, "01_SYSTEM_ARCHITECTURE.txt", "System architecture", listOf("separated core modules and versioned contracts", "local data, audit, orchestration and capability checks"), listOf("Core Kotlin source compilation", "local scope and chain-of-custody checks"), listOf("Optional isolated Linux worker and authenticated IPC", "complete crash recovery and migration/device matrix")),
        item(2, "02_LOCAL_INTELLIGENCE_CORE.txt", "Local intelligence core", listOf("deterministic rules, signatures, static adapters, correlation and local retrieval", "no hosted inference fallback"), listOf("rule and source-analysis unit fixtures", "schema-analysis regression fixtures"), listOf("Full AST/data-flow/taint engines for all languages", "reviewed signed rule-pack update pipeline")),
        item(3, "03_SECURITY_KNOWLEDGE_DATABASE.txt", "Security knowledge database", listOf("local SQLite/FTS knowledge store", "source attribution and stale-data labels"), listOf("local knowledge initialization and search smoke checks"), listOf("verified signed advisory feeds and transactional snapshot rollback", "complete OSV/CVE/CISA/vendor ingestion")),
        item(4, "04_UNIVERSAL_PENETRATION_TESTING.txt", "Universal assessment lifecycle", listOf("authorization manifest, safe test catalogue, findings and report workflow", "bounded passive HTTP and TCP connect checks"), listOf("scope validation and bounded local crawler fixture"), listOf("authenticated BOLA/BFLA and full DAST/API/network test families", "full coverage denominator across live environments")),
        item(5, "05_WEB_API_SECURITY.txt", "Web application and API security", listOf("HTTP headers/cookies/TLS observations", "OpenAPI JSON/YAML, GraphQL SDL and SOAP WSDL static review"), listOf("OpenAPI YAML, GraphQL and WSDL fixtures", "passive HTTP crawler fixture"), listOf("authenticated runtime authorization, GraphQL depth/complexity and SOAP runtime tests", "full parameter/endpoint DAST")),
        item(6, "06_NETWORK_ENTERPRISE_SECURITY.txt", "Network and enterprise security", listOf("explicit-IP TCP connect and TLS certificate checks", "static network/IaC configuration observations"), listOf("TCP probe guard and CIDR numeric parsing checks"), listOf("authorized range inventory and service fingerprinting", "AD/Entra/Kerberos/SSO read-only provider integrations")),
        item(7, "07_ANDROID_MOBILE_SECURITY.txt", "Android and mobile security", listOf("Android source/manifest configuration heuristics", "APK/AAB binary inventory for manifest/DEX presence"), listOf("ZIP archive inventory and static Android fixture checks"), listOf("binary AXML decoding, signature verification and MobSF adapter", "device-side sandboxed APK analysis and API/ABI matrix")),
        item(8, "08_WORDPRESS_WOOCOMMERCE_SECURITY.txt", "WordPress and WooCommerce security", listOf("PHP source heuristics for REST/AJAX/nonce/capability/upload/deserialization and Woo ownership", "component metadata and remediation playbook"), listOf("WordPress static source fixture and secret redaction test"), listOf("authenticated read-only WP runtime adapter, roles/multisite/plugin state", "WooCommerce synthetic checkout/webhook sandbox validation")),
        item(9, "09_CLOUD_IDENTITY_CONTAINER_SECURITY.txt", "Cloud, identity and container security", listOf("static Terraform/Kubernetes/Docker/CI configuration review"), listOf("static configuration analyzer fixtures"), listOf("AWS/Azure/GCP/Entra read-only connectors", "container registry/image scanning and live IAM posture assessment")),
        item(10, "10_ADVANCED_RED_TEAM_INTELLIGENCE.txt", "Advanced defensive red-team intelligence", listOf("defensive ATT&CK mappings and benign simulation catalog", "no stealth, persistence, credential theft or lateral movement"), listOf("offline synthetic lab scenario smoke tests"), listOf("real enterprise telemetry integrations and calibrated ATT&CK coverage", "isolated hypervisor/container lab executor")),
        item(11, "11_GITHUB_TOOL_INTELLIGENCE.txt", "GitHub tool and supply-chain intelligence", listOf("tool registry metadata, license/provenance review fields and adapter contracts"), listOf("registry parsing and policy checks"), listOf("live GitHub advisory/release verification and repository sandbox builds", "signed tool package updates and rollback")),
        item(12, "12_ATTACK_GRAPH_AND_RISK_ENGINE.txt", "Attack graph and risk engine", listOf("evidence-based graph nodes/edges and observed/inferred distinction", "transparent risk prioritization"), listOf("graph structure and finding correlation checks"), listOf("full identity/cloud relationship collection and calibrated path confidence", "visual interactive graph and remediation-cut optimization")),
        item(13, "13_REMEDIATION_PATCH_ENGINE.txt", "Remediation and patch engine", listOf("framework-aware remediation recipes, exact snippet preview and approval fields", "backup/rollback/retest plan output"), listOf("patch path/scope validation and remediation model tests"), listOf("safe patch application, staging runner and automated rollback", "production approval/deploy monitoring integration")),
        item(14, "14_THREAT_INTELLIGENCE_AND_FORENSICS.txt", "Threat intelligence and forensics", listOf("local file hashing, timeline/evidence metadata and hash-linked custody ledger", "indicator matching separated from compromise proof"), listOf("chain-of-custody tamper detection and evidence redaction checks"), listOf("signed external evidence witness and full forensic format parsers", "current trusted advisory/IOC ingestion with provenance and decay")),
        item(15, "15_SECURITY_AUTOMATION_AND_MONITORING.txt", "Security automation and monitoring", listOf("bounded encrypted queue with WorkManager one-time jobs and network constraints", "process-restart recovery, cancellation and authorization recheck before claim", "local audit history"), listOf("job/scope and cancellation code checks", "scheduler recovery regression sources"), listOf("real-time execution is not guaranteed; Android may defer background work", "always-on monitoring/foreground-service notification lifecycle is unsupported")),
        item(16, "16_SECURITY_LAB_AND_SIMULATION.txt", "Security lab and simulation", listOf("offline synthetic fixtures and pass-after-fix scenarios"), listOf("local lab catalog smoke checks"), listOf("isolated disposable VM/container orchestration and automated teardown", "real vulnerable training app integration")),
        item(17, "17_DASHBOARD_UX_AND_REPORTING.txt", "Dashboard UX and reporting", listOf("existing dark/red Android dashboard and RTL UI preserved", "JSON/HTML/PDF reports, finding and evidence detail"), listOf("report model and JSON/HTML export smoke checks"), listOf("independent navigation screens and interactive graph visualization", "broad accessibility/language/device testing")),
        item(18, "18_SECURITY_POLICY_AND_PERMISSIONS.txt", "Security policy and authorization", listOf("exact host/path/port scope, exclusions, time window and request budgets", "private IP requires explicit numeric CIDR; redirects are not followed"), listOf("scope, redirect, query-string and numeric CIDR boundary tests"), listOf("complete CIDR enforcement for every external adapter and signed child scope tokens", "full threat-hardening review on device")),
        item(19, "19_TESTING_BENCHMARK_AND_QA.txt", "Testing, benchmark and QA", listOf("core unit/smoke tests, static preflight and regression fixtures"), listOf("v0.8.0 integration checks described in release test log"), listOf("Android Gradle/JUnit/lint, API/ABI/resource/device and install/upgrade tests", "measured precision/recall datasets and benchmark suite")),
        item(20, "20_ANDROID_LINUX_BUILD_AND_RELEASE.txt", "Android, local Linux and release", listOf("Android project source, GitHub Actions workflow, versioning and checksum docs"), listOf("core Kotlin source compile and ZIP integrity checks"), listOf("Android APK/AAB build, signed install/upgrade validation", "optional independent Linux worker and SBOM/license release gate execution")),
        item(21, "21_EXECUTION_ORDER_AND_ACCEPTANCE.txt", "Execution order and acceptance", listOf("ordered specification ledger, release gates and explicit limitations"), listOf("sequential 00–23 presence/ordering check"), listOf("all acceptance items backed by real device/production-like lab evidence")),
        item(22, "22_WEBSITE_SECURITY_SPECIALIST.txt", "Website Security Specialist v2", listOf("website engagement model, coverage matrix, test plans, evidence records, source archive mapping", "bounded passive crawler with IP pinning and no credential submission"), listOf("specialist coverage and passive crawler regression checks", "schema/WordPress analyzer fixtures"), listOf("full DNS/sitemap/architecture discovery and authenticated/staging web assessment", "complete engagement intake UI and runtime WordPress/Woo adapters")),
        item(23, "23_WEBSITE_REMEDIATION_PLAYBOOK.txt", "Website remediation playbook", listOf("14 remediation recipes, reviewable repair plans and developer ticket export", "patch preview, rollback and retest checklists"), listOf("remediation model and static WordPress playbook checks"), listOf("framework parser-backed patch generation and staging execution", "automated post-fix verification across real supported frameworks"))
    )

    fun snapshot(): SpecificationCoverageSummaryV080 {
        val executionRecords = entries.map { item ->
            SpecificationExecutionRecordV1(
                number = item.number,
                filename = item.fileName,
                status = item.status,
                changedFiles = item.implementedAreas,
                testReferences = item.verifiedChecks,
                limitations = item.remainingWork
            )
        }
        val validation = SequentialSpecificationLedgerV1.validate(executionRecords, expectedLast = 23)
        return SpecificationCoverageSummaryV080(
            expectedDocuments = 24,
            presentDocuments = entries.size,
            testedWholeDocuments = entries.count { it.status == SpecificationImplementationStatus.TESTED },
            implementedWholeDocuments = entries.count { it.status == SpecificationImplementationStatus.IMPLEMENTED },
            partiallySupportedDocuments = entries.count { it.status == SpecificationImplementationStatus.PARTIALLY_SUPPORTED },
            unsupportedDocuments = entries.count { it.status == SpecificationImplementationStatus.UNSUPPORTED || it.status == SpecificationImplementationStatus.BLOCKED },
            sequenceValid = validation.valid,
            items = entries
        )
    }

    private fun item(number: Int, fileName: String, title: String, implemented: List<String>, tests: List<String>, remaining: List<String>) =
        SpecificationCoverageItemV080(number, fileName, title, SpecificationImplementationStatus.PARTIALLY_SUPPORTED, implemented, tests, remaining)
}
