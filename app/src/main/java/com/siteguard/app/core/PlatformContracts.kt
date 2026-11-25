package com.siteguard.app.core

import org.json.JSONArray
import org.json.JSONObject

/** Versioned ports keep UI, orchestration, scanners and persistence independently replaceable. */
data class ScannerRequestV1(
    val target: String,
    val authorization: AuthorizationManifest,
    val allowPrivateNetwork: Boolean
)

interface ScannerAdapterV1 {
    val adapterId: String
    val contractVersion: Int get() = 1
    suspend fun scan(request: ScannerRequestV1): ScanResult
}

interface EvidenceProviderV1 {
    val contractVersion: Int get() = 1
    fun evidenceFor(finding: Finding): EvidenceRecordV1
}

data class EvidenceRecordV1(
    val evidenceId: String,
    val asset: String,
    val location: String,
    val method: String,
    val capturedAtEpochMs: Long,
    val excerpt: String,
    val hashSha256: String
)

interface KnowledgeProviderV1 {
    val contractVersion: Int get() = 1
    fun lookup(cwe: String): WeaknessKnowledge?
    fun version(): String
}

interface RemediationProviderV1 {
    val contractVersion: Int get() = 1
    fun createPlan(finding: Finding): RemediationPlanV1
}

data class RemediationStepV1(val order: Int, val title: String, val instruction: String, val requiresApproval: Boolean)
data class RemediationPlanV1(
    val findingId: String,
    val rootCause: String,
    val steps: List<RemediationStepV1>,
    val verification: String,
    val rollback: String,
    val stagingOnly: Boolean = true,
    val automaticPatchAvailable: Boolean = false,
    val regressionTests: List<String> = emptyList(),
    val stagingValidation: String = "ابتدا در محیط staging با داده آزمایشی و پشتیبان بررسی کنید.",
    val postFixRetest: String = verification,
    val patchDiffStatus: String = "Diff تولید نشده؛ زمینه کامل سورس/پیکربندی برای patch ایمن در دسترس نیست.",
    val proposedPatchDiff: String? = null
)

interface ReportExporterV1 {
    val contractVersion: Int get() = 1
    fun exportScan(result: ScanResult): String
    fun exportSbom(inventory: DependencyInventory, projectName: String): String
}

object DefaultEvidenceProvider : EvidenceProviderV1 {
    override fun evidenceFor(finding: Finding): EvidenceRecordV1 {
        val raw = "${finding.affectedAsset}|${finding.exactLocation}|${EvidenceSanitizer.sanitize(finding.evidence)}|${finding.detectedAtEpochMs}"
        val hash = java.security.MessageDigest.getInstance("SHA-256")
            .digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
        return EvidenceRecordV1(
            evidenceId = "EVD-${hash.take(16)}", asset = finding.affectedAsset,
            location = finding.exactLocation,
            method = "${finding.detectionMethod}; SHA-256 of canonical finding metadata and sanitized evidence excerpt (not the full original file).",
            capturedAtEpochMs = finding.detectedAtEpochMs, excerpt = EvidenceSanitizer.sanitize(finding.evidence),
            hashSha256 = hash
        )
    }
}

object DefaultRemediationProvider : RemediationProviderV1 {
    override fun createPlan(finding: Finding): RemediationPlanV1 = RemediationPlanV1(
        findingId = finding.id,
        rootCause = finding.description,
        steps = listOf(
            RemediationStepV1(1, "بازبینی علت", "محل دقیق و شواهد را با کد/پیکربندی واقعی تطبیق دهید؛ heuristic را بدون بررسی تأییدشده فرض نکنید.", false),
            RemediationStepV1(2, "آماده‌سازی اصلاح", finding.remediation, true),
            RemediationStepV1(3, "آزمون staging", finding.verificationProcedure, true),
            RemediationStepV1(4, "انتشار کنترل‌شده", "پس از تأیید مالک و تهیه نسخه پشتیبان، تغییر را در پنجره انتشار مجاز اعمال کنید.", true)
        ),
        verification = finding.verificationProcedure + " نتیجه مورد انتظار: " + finding.expectedResult,
        rollback = "نسخه پشتیبان/تغییر قبلی را برگردانید، سپس همان آزمون را دوباره اجرا و residual risk را ثبت کنید.",
        regressionTests = listOf(
            finding.safeValidation,
            when (finding.cwe) {
                "CWE-89" -> "تست ورودی‌های عادی و رشته‌های ویژه با query پارامتری؛ خروجی باید بدون تغییر ساختار SQL باقی بماند."
                "CWE-79" -> "تست متن شامل کاراکترهای HTML در context خروجی؛ باید به‌صورت متن امن نمایش داده شود، نه markup اجرایی."
                "CWE-352" -> "تست درخواست تغییردهنده با nonce معتبر، نامعتبر و مفقود؛ دو حالت آخر باید رد شوند."
                "CWE-862", "CWE-306" -> "تست دسترسی با نقش مجاز و غیرمجاز؛ نقش فاقد capability باید رد شود."
                "CWE-434" -> "تست پسوند دوگانه، MIME جعلی، محتوای نامعتبر و سقف اندازه؛ فایل غیرمجاز نباید ذخیره/اجرا شود."
                else -> "برای مسیر اصلاح‌شده یک تست regression مثبت و منفی بنویسید و نتیجه را ثبت کنید."
            }
        ),
        stagingValidation = "تغییر را فقط روی staging همسان با نسخه framework/plugin اعمال کنید؛ پیش از production backup و تأیید مالک لازم است.",
        postFixRetest = finding.verificationProcedure + " سپس همان ورودی/مسیر را پس از اصلاح تکرار و نتیجه واقعی را ثبت کنید.",
        patchDiffStatus = "Diff خودکار تولید نشد؛ snippet محدود یافته برای فهم کامل متغیرها، framework و side effect کافی نیست.",
        proposedPatchDiff = null
    )
}

object JsonReportExporter : ReportExporterV1 {
    override fun exportScan(result: ScanResult): String = JSONObject().apply {
        put("schema_version", SiteGuardBuildInfo.REPORT_SCHEMA_VERSION)
        put("product", "SiteGuard Android")
        put("version", SiteGuardBuildInfo.VERSION_NAME)
        put("target", EvidenceSanitizer.sanitize(result.host).take(253))
        put("http_status", result.httpStatus ?: JSONObject.NULL)
        put("scanned_at_epoch_ms", result.scannedAt)
        put("authorization_id", result.authorizationId)
        put("connected_address", result.connectedAddress)
        put("scope", "single exact host and port; passive HTTP GET; redirects disabled")
        put("message", EvidenceSanitizer.sanitize(result.message).take(2_000))
        put("coverage_notes", JSONArray(result.coverageNotes.map { EvidenceSanitizer.sanitize(it).take(1_000) }))
        put("findings", JSONArray().apply { result.findings.forEach { put(findingJson(it)) } })
        put("limitations", JSONArray(listOf("This is a bounded passive baseline, not a full security assessment.", "No exploit, brute force, authenticated tests, crawling or state-changing requests were performed.")))
    }.toString(2)

    override fun exportSbom(inventory: DependencyInventory, projectName: String): String {
        val serial = java.util.UUID.randomUUID().toString()
        return JSONObject().apply {
            put("bomFormat", "CycloneDX")
            put("specVersion", "1.5")
            put("serialNumber", "urn:uuid:$serial")
            put("version", 1)
            put("metadata", JSONObject().put("component", JSONObject()
                .put("type", "application").put("name", projectName.ifBlank { "Imported project" })))
            put("components", JSONArray().apply {
                inventory.records.forEachIndexed { index, dependency ->
                    val purl = when (dependency.ecosystem) {
                        "npm" -> "pkg:npm/${dependency.name}@${dependency.declaredVersion}"
                        "composer" -> "pkg:composer/${dependency.name}@${dependency.declaredVersion}"
                        "pypi" -> "pkg:pypi/${dependency.name}@${dependency.declaredVersion}"
                        "maven" -> "pkg:maven/${dependency.name.replace(':', '/') }@${dependency.declaredVersion}"
                        else -> "pkg:generic/${dependency.name}@${dependency.declaredVersion}"
                    }
                    put(JSONObject().apply {
                        put("type", "library"); put("bom-ref", purl); put("name", dependency.name)
                        put("version", dependency.declaredVersion); put("purl", purl)
                        put("scope", if (dependency.direct) "required" else "optional")
                        put("properties", JSONArray().put(JSONObject().put("name", "siteguard:manifest-path").put("value", dependency.manifestPath)))
                    })
                }
            })
            put("properties", JSONArray().put(JSONObject().put("name", "siteguard:limitations").put("value", inventory.limitations.joinToString(" "))))
        }.toString(2)
    }

    fun projectJson(project: ProjectAuditResult): JSONObject = JSONObject().apply {
        put("archive", project.archiveName)
        put("files_discovered", project.filesDiscovered)
        put("files_scanned", project.filesScanned)
        put("expanded_bytes_read", project.totalExpandedBytesRead)
        put("languages", JSONObject(project.languages))
        put("is_wordpress", project.isWordPress)
        put("is_woocommerce", project.isWooCommerce)
        put("website_components", JSONArray().apply { project.websiteComponents.forEach { component -> put(JSONObject()
            .put("type", component.type).put("name", component.name).put("version", component.version)
            .put("source_path", component.sourcePath)) } })
        put("dependencies", JSONArray().apply {
            project.dependencies.records.forEach { dep -> put(JSONObject().apply {
                put("ecosystem", dep.ecosystem); put("name", dep.name); put("version", dep.declaredVersion)
                put("manifest", dep.manifestPath); put("direct", dep.direct); put("version_pinned", dep.versionPinned)
            }) }
        })
        put("findings", JSONArray().apply { project.findings.forEach { put(findingJson(it)) } })
        put("domain_coverage", JSONArray().apply { project.domainCoverage.forEach { coverage -> put(JSONObject()
            .put("domain", coverage.domain).put("state", coverage.state).put("files_examined", coverage.filesExamined)
            .put("findings", coverage.findings).put("notes", coverage.notes)) } })
        put("defensive_attack_techniques", JSONArray().apply { project.defensiveTechniques.forEach { technique -> put(JSONObject()
            .put("technique_id", technique.techniqueId).put("name", technique.name).put("level", technique.level)
            .put("public_source", technique.publicSource).put("prerequisites", technique.prerequisites)
            .put("defensive_indicators", JSONArray(technique.defensiveIndicators)).put("safe_simulation", technique.safeSimulation)
            .put("expected_telemetry", JSONArray(technique.expectedTelemetry)).put("detection_logic", technique.detectionLogic)
            .put("mitigation", technique.mitigation).put("validation", technique.validation)) } })
        put("evidence_graph", JSONObject().apply {
            put("nodes", JSONArray().apply { project.evidenceGraph.nodes.forEach { node -> put(JSONObject()
                .put("id", node.id).put("type", node.type).put("label", node.label).put("source_reference", node.sourceReference)) } })
            put("edges", JSONArray().apply { project.evidenceGraph.edges.forEach { edge -> put(JSONObject()
                .put("from", edge.from).put("to", edge.to).put("relationship", edge.relationship).put("evidence_reference", edge.evidenceReference)) } })
            put("limitations", JSONArray(project.evidenceGraph.limitations))
        })
        put("knowledge_pack", JSONObject().apply {
            val status = LocalSecurityKnowledgePack.status()
            put("version", status.packVersion).put("mode", status.mode).put("is_live_feed", status.isLiveFeed)
            put("last_updated_epoch_ms", status.lastUpdatedEpochMs ?: JSONObject.NULL).put("note", status.note)
            put("source_references", JSONArray().apply { LocalSecurityKnowledgePack.sources.forEach { source -> put(JSONObject()
                .put("id", source.sourceId).put("publisher", source.publisher).put("url", source.url).put("topic", source.topic)) } })
        })
        put("limitations", JSONArray(project.limitations + project.dependencies.limitations))
        put("skipped_entries", JSONArray(project.skippedEntries))
    }

    private fun safeReportText(value: String, maxLength: Int = 4_000): String =
        EvidenceSanitizer.sanitize(value).take(maxLength)

    fun findingJson(f: Finding): JSONObject = JSONObject().apply {
        put("id", safeReportText(f.id, 200)); put("title", safeReportText(f.title, 500)); put("category_cwe", safeReportText(f.cwe, 80))
        put("severity", f.severity.name); put("status", f.status.name); put("confidence", safeReportText(f.confidence, 80))
        put("affected_asset", safeReportText(f.affectedAsset, 1_000)); put("exact_location", safeReportText(f.exactLocation, 1_000))
        put("detection_method", safeReportText(f.detectionMethod, 300)); put("tool_version", safeReportText(f.toolVersion, 80))
        put("detected_at_epoch_ms", f.detectedAtEpochMs); put("evidence", safeReportText(f.evidence, 1_000))
        put("description", safeReportText(f.description)); put("business_impact", safeReportText(f.businessImpact))
        put("exploit_prerequisites", safeReportText(f.exploitPrerequisites)); put("remediation", safeReportText(f.remediation))
        put("safe_validation", safeReportText(f.safeValidation)); put("not_tested", safeReportText(f.notTested))
        put("verification", safeReportText(f.verificationProcedure)); put("expected_result", safeReportText(f.expectedResult))
        put("actual_result", safeReportText(f.actualResult)); put("residual_risk", safeReportText(f.residualRisk))
        val evidence = DefaultEvidenceProvider.evidenceFor(f)
        put("evidence_reference", JSONObject()
            .put("id", safeReportText(evidence.evidenceId, 200)).put("sha256", safeReportText(evidence.hashSha256, 64)).put("method", safeReportText(evidence.method, 200)))
        val priority = RiskEngine.prioritize(f)
        put("triage_priority", JSONObject().put("score", priority.score).put("band", priority.band)
            .put("explanation", safeReportText(priority.explanation, 1_000)))
        val evidenceQuality = EvidenceConfidenceEngineV1.assess(f)
        put("evidence_quality", JSONObject().apply {
            put("score", evidenceQuality.score); put("band", evidenceQuality.band)
            put("factors", JSONArray(evidenceQuality.factors)); put("caveat", evidenceQuality.caveat)
        })
        val plan = DefaultRemediationProvider.createPlan(f)
        put("remediation_plan", JSONObject().apply {
            put("root_cause_hypothesis", safeReportText(plan.rootCause))
            put("steps", JSONArray().apply { plan.steps.forEach { step -> put(JSONObject()
                .put("order", step.order).put("title", safeReportText(step.title, 500)).put("instruction", safeReportText(step.instruction))
                .put("requires_approval", step.requiresApproval)) } })
            put("verification", safeReportText(plan.verification))
            put("regression_tests", JSONArray(plan.regressionTests.map { safeReportText(it, 1_000) }))
            put("staging_validation", safeReportText(plan.stagingValidation))
            put("post_fix_retest", safeReportText(plan.postFixRetest))
            put("patch_diff_status", plan.patchDiffStatus)
            put("proposed_patch_diff", plan.proposedPatchDiff?.let { safeReportText(it, 8_000) } ?: JSONObject.NULL)
            put("rollback", safeReportText(plan.rollback))
            put("staging_only", plan.stagingOnly)
            put("automatic_patch_available", plan.automaticPatchAvailable)
        })
    }
}
