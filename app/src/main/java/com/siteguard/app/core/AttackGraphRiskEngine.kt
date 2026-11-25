package com.siteguard.app.core

import java.util.ArrayDeque

/** Evidence-backed graph. Inferred links are retained but never silently treated as observed. */
enum class AttackGraphNodeType {
    ASSET, HOSTNAME, IP, ENDPOINT, IDENTITY, ROLE, SOFTWARE, VULNERABILITY,
    CONFIGURATION, TRUST_RELATIONSHIP, EVIDENCE, CONTROL, REMEDIATION, BUSINESS_PROCESS
}

enum class RelationshipEvidenceType { OBSERVED, INFERRED }

data class AttackGraphNodeV1(
    val id: String,
    val type: AttackGraphNodeType,
    val label: String,
    val sourceEvidenceId: String,
    val observedAtEpochMs: Long,
    val provenance: String
)

data class AttackGraphEdgeV1(
    val id: String,
    val fromNodeId: String,
    val toNodeId: String,
    val relationship: String,
    val evidenceId: String,
    val observedAtEpochMs: Long,
    val confidence: Double,
    val provenance: String,
    val validityUntilEpochMs: Long? = null,
    val evidenceType: RelationshipEvidenceType = RelationshipEvidenceType.OBSERVED,
    val prerequisites: List<String> = emptyList(),
    val trustBoundary: String = "نامشخص",
    val requiredPrivileges: String = "نامشخص"
)

data class AttackGraphPathV1(
    val nodeIds: List<String>,
    val edgeIds: List<String>,
    val includesInferredRelationships: Boolean,
    val weakestLinkConfidence: Double,
    val explanation: String,
    val label: String = "مسیر کاندید؛ بهره‌پذیری اثبات نشده است"
)

data class AttackGraphValidation(val valid: Boolean, val issues: List<String>)

data class AttackGraphV1(val nodes: List<AttackGraphNodeV1>, val edges: List<AttackGraphEdgeV1>) {
    companion object {
        /** Converts findings to a minimal graph using only canonical finding evidence and exact affected assets. */
        fun fromFindings(findings: List<Finding>): AttackGraphV1 {
            val nodes = linkedMapOf<String, AttackGraphNodeV1>()
            val edges = mutableListOf<AttackGraphEdgeV1>()
            findings.forEach { finding ->
                val evidence = DefaultEvidenceProvider.evidenceFor(finding)
                val assetLabel = finding.affectedAsset.ifBlank { "local/imported asset" }
                val assetId = "asset:${assetLabel.hashCode()}"
                val findingNodeId = "finding:${finding.id}"
                val evidenceNodeId = "evidence:${evidence.evidenceId}"
                nodes.putIfAbsent(assetId, AttackGraphNodeV1(
                    assetId, AttackGraphNodeType.ASSET, assetLabel, evidence.evidenceId,
                    finding.detectedAtEpochMs, "exact affectedAsset from finding"
                ))
                nodes[findingNodeId] = AttackGraphNodeV1(
                    findingNodeId, AttackGraphNodeType.VULNERABILITY, finding.title, evidence.evidenceId,
                    finding.detectedAtEpochMs, "finding:${finding.id}"
                )
                nodes[evidenceNodeId] = AttackGraphNodeV1(
                    evidenceNodeId, AttackGraphNodeType.EVIDENCE, evidence.evidenceId, evidence.evidenceId,
                    evidence.capturedAtEpochMs, "DefaultEvidenceProvider SHA-256 metadata"
                )
                edges += AttackGraphEdgeV1(
                    "edge:${finding.id}:asset-finding", assetId, findingNodeId, "HAS_RECORDED_FINDING",
                    evidence.evidenceId, finding.detectedAtEpochMs, 1.0, "Finding affectedAsset + sanitized evidence metadata",
                    evidenceType = RelationshipEvidenceType.OBSERVED
                )
                edges += AttackGraphEdgeV1(
                    "edge:${finding.id}:finding-evidence", findingNodeId, evidenceNodeId, "SUPPORTED_BY_EVIDENCE",
                    evidence.evidenceId, finding.detectedAtEpochMs, 1.0, "canonical finding evidence reference",
                    evidenceType = RelationshipEvidenceType.OBSERVED
                )
            }
            return AttackGraphV1(nodes.values.toList(), edges.distinctBy { it.id })
        }
    }

    fun validate(nowEpochMs: Long = System.currentTimeMillis()): AttackGraphValidation {
        val issues = mutableListOf<String>()
        val ids = nodes.map { it.id }
        if (ids.any(String::isBlank)) issues += "شناسه گره خالی است."
        if (ids.size != ids.distinct().size) issues += "شناسه گره تکراری است."
        val edgeIds = edges.map { it.id }
        if (edgeIds.any(String::isBlank) || edgeIds.size != edgeIds.distinct().size) issues += "شناسه یال خالی یا تکراری است."
        val nodeSet = ids.toSet()
        edges.forEach { edge ->
            if (edge.fromNodeId !in nodeSet || edge.toNodeId !in nodeSet) issues += "یال ${edge.id} به گره ناشناخته اشاره می‌کند."
            if (edge.evidenceId.isBlank() || edge.provenance.isBlank()) issues += "یال ${edge.id} فاقد شواهد یا provenance است."
            if (edge.confidence !in 0.0..1.0) issues += "اطمینان یال ${edge.id} خارج از بازه ۰ تا ۱ است."
            if (edge.observedAtEpochMs <= 0 || edge.observedAtEpochMs > nowEpochMs) issues += "زمان یال ${edge.id} معتبر نیست."
            if (edge.validityUntilEpochMs != null && edge.validityUntilEpochMs < edge.observedAtEpochMs) issues += "بازه اعتبار یال ${edge.id} نامعتبر است."
        }
        return AttackGraphValidation(issues.isEmpty(), issues.distinct())
    }

    /** Finds bounded candidate paths from edges with evidence; never labels them exploitable. */
    fun candidatePaths(
        startNodeId: String,
        targetNodeId: String,
        maxDepth: Int = 5,
        nowEpochMs: Long = System.currentTimeMillis()
    ): List<AttackGraphPathV1> {
        if (validate(nowEpochMs).valid.not() || maxDepth < 1) return emptyList()
        if (nodes.none { it.id == startNodeId } || nodes.none { it.id == targetNodeId }) return emptyList()
        val adjacency = edges.filter {
            it.evidenceId.isNotBlank() && it.provenance.isNotBlank() &&
                it.confidence in 0.0..1.0 && (it.validityUntilEpochMs == null || nowEpochMs <= it.validityUntilEpochMs)
        }.groupBy { it.fromNodeId }
        data class Walk(val nodeIds: List<String>, val edgeIds: List<String>, val pathEdges: List<AttackGraphEdgeV1>)
        val queue = ArrayDeque<Walk>()
        queue.add(Walk(listOf(startNodeId), emptyList(), emptyList()))
        val results = mutableListOf<AttackGraphPathV1>()
        while (queue.isNotEmpty() && results.size < 64) {
            val current = queue.removeFirst()
            val last = current.nodeIds.last()
            if (last == targetNodeId && current.edgeIds.isNotEmpty()) {
                val inferred = current.pathEdges.any { it.evidenceType == RelationshipEvidenceType.INFERRED }
                val weakest = current.pathEdges.minOfOrNull { it.confidence } ?: 0.0
                results += AttackGraphPathV1(
                    current.nodeIds, current.edgeIds, inferred, weakest,
                    "مسیر بر اساس ${current.pathEdges.size} رابطه مستند ساخته شده است؛ پیش‌نیازها و مرزهای اعتماد باید دستی اعتبارسنجی شوند."
                )
                continue
            }
            if (current.edgeIds.size >= maxDepth) continue
            adjacency[last].orEmpty().forEach { edge ->
                if (edge.toNodeId !in current.nodeIds) {
                    queue.add(Walk(current.nodeIds + edge.toNodeId, current.edgeIds + edge.id, current.pathEdges + edge))
                }
            }
        }
        return results
    }
}

data class RiskFactorsV1(
    val cvssScore: Double? = null,
    val cvssSource: String = "",
    val assetCriticality: Int = 3,
    val exposure: Int = 3,
    val exploitPrerequisiteDifficulty: Int = 3,
    val cisaKevListed: Boolean = false,
    val compensatingControls: Int = 0,
    val dataSensitivity: Int = 3,
    val businessImpact: Int = 3
)

data class RiskFactorContribution(val name: String, val input: String, val contribution: Int, val source: String)
data class ExplainableRiskAssessmentV1(
    val internalScore: Int,
    val band: String,
    val contributions: List<RiskFactorContribution>,
    val caveat: String = "امتیاز داخلی SiteGuard است؛ جایگزین CVSS یا تحلیل کسب‌وکار نیست."
)

object ExplainableRiskEngineV1 {
    fun assess(f: RiskFactorsV1): ExplainableRiskAssessmentV1 {
        val criticality = f.assetCriticality.coerceIn(1, 5)
        val exposure = f.exposure.coerceIn(1, 5)
        val difficulty = f.exploitPrerequisiteDifficulty.coerceIn(1, 5)
        val controls = f.compensatingControls.coerceIn(0, 5)
        val sensitivity = f.dataSensitivity.coerceIn(1, 5)
        val impact = f.businessImpact.coerceIn(1, 5)
        val cvss = f.cvssScore?.coerceIn(0.0, 10.0)
        val rows = listOf(
            RiskFactorContribution("اهمیت دارایی", "$criticality/5", criticality * 5, "ارزیابی مالک دارایی"),
            RiskFactorContribution("در معرض اینترنت/شبکه", "$exposure/5", exposure * 5, "وضعیت exposure ثبت‌شده"),
            RiskFactorContribution("سهولت پیش‌نیاز", "$difficulty/5", (6 - difficulty) * 3, "پیش‌نیازهای تست ثبت‌شده"),
            RiskFactorContribution("CISA KEV", if (f.cisaKevListed) "Listed" else "Not listed/unknown", if (f.cisaKevListed) 10 else 0, "فهرست KEV؛ وضعیت باید با snapshot تازه تأیید شود"),
            RiskFactorContribution("حساسیت داده", "$sensitivity/5", sensitivity * 4, "طبقه‌بندی داده توسط مالک"),
            RiskFactorContribution("اثر کسب‌وکار", "$impact/5", impact * 4, "تحلیل اثر کسب‌وکار"),
            RiskFactorContribution("کنترل جبرانی", "$controls/5", -controls * 4, "کنترل‌های جبرانی مستند"),
            RiskFactorContribution("CVSS ورودی", cvss?.toString() ?: "ارائه نشده", cvss?.let { (it * 2).toInt() } ?: 0, f.cvssSource.ifBlank { "CVSS محاسبه نشده/منبعی ارائه نشده" })
        )
        val score = rows.sumOf { it.contribution }.coerceIn(0, 100)
        val band = when {
            score >= 75 -> "بحرانی/فوری"
            score >= 55 -> "بالا"
            score >= 30 -> "متوسط"
            else -> "پایین"
        }
        return ExplainableRiskAssessmentV1(score, band, rows)
    }
}
