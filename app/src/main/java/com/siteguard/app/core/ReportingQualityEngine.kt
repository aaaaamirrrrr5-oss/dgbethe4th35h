package com.siteguard.app.core

import java.util.Locale


enum class TestExecutionStatus { EXECUTED, SKIPPED, BLOCKED, FAILED }

data class TestExecutionRecordV1(
    val testId: String,
    val domain: String,
    val status: TestExecutionStatus,
    val reason: String,
    val evidenceIds: List<String> = emptyList(),
    val durationMs: Long? = null
)

data class TestCoverageSummaryV1(
    val denominator: Int,
    val executed: Int,
    val skipped: Int,
    val blocked: Int,
    val failed: Int,
    val coveragePercent: Double,
    val domainCounts: Map<String, Int>
)

object TestCoverageCalculatorV1 {
    fun summarize(records: List<TestExecutionRecordV1>): TestCoverageSummaryV1 {
        val executed = records.count { it.status == TestExecutionStatus.EXECUTED }
        val skipped = records.count { it.status == TestExecutionStatus.SKIPPED }
        val blocked = records.count { it.status == TestExecutionStatus.BLOCKED }
        val failed = records.count { it.status == TestExecutionStatus.FAILED }
        val denominator = records.size
        return TestCoverageSummaryV1(
            denominator, executed, skipped, blocked, failed,
            if (denominator == 0) 0.0 else (executed * 100.0 / denominator),
            records.groupingBy { it.domain }.eachCount().toSortedMap()
        )
    }
}

data class LabeledFixtureMetricsV1(
    val truePositive: Int,
    val falsePositive: Int,
    val trueNegative: Int,
    val falseNegative: Int,
    val fixtureDataset: String,
    val datasetLimitations: String
) {
    init { require(listOf(truePositive, falsePositive, trueNegative, falseNegative).all { it >= 0 }) }
    val precision: Double? get() = ratio(truePositive, truePositive + falsePositive)
    val recall: Double? get() = ratio(truePositive, truePositive + falseNegative)
    val falsePositiveRate: Double? get() = ratio(falsePositive, falsePositive + trueNegative)
    val accuracy: Double? get() = ratio(truePositive + trueNegative, truePositive + falsePositive + trueNegative + falseNegative)
    private fun ratio(n: Int, d: Int): Double? = if (d == 0) null else n.toDouble() / d.toDouble()
}

enum class AcceptanceStatus { PASS, FAIL, NOT_RUN, BLOCKED }

data class AcceptanceCheckV1(val id: String, val title: String, val status: AcceptanceStatus, val evidence: String)
data class AcceptanceSummaryV1(val checks: List<AcceptanceCheckV1>, val releaseAllowed: Boolean, val blockers: List<String>)

object ReleaseAcceptanceCheckerV1 {
    fun evaluate(checks: List<AcceptanceCheckV1>): AcceptanceSummaryV1 {
        val blockers = checks.filter { it.status != AcceptanceStatus.PASS }.map { "${it.id}: ${it.status} — ${it.evidence}" }
        return AcceptanceSummaryV1(checks.toList(), blockers.isEmpty() && checks.isNotEmpty(), blockers)
    }
}

data class SecurityReportV1(
    val product: String,
    val version: String,
    val generatedAtEpochMs: Long,
    val scopeDescription: String,
    val authorizationId: String,
    val methodology: String,
    val coverage: TestCoverageSummaryV1,
    val findings: List<Finding>,
    val limitations: List<String>,
    val evidenceReferences: List<String>,
    val remediationSummary: List<String>,
    val retestSummary: String,
    val websiteSpecialistCoverage: List<String> = emptyList(),
    val architectureRelationships: List<String> = emptyList(),
    val websiteTestPlans: List<String> = emptyList(),
    val websiteEvidenceRecords: List<String> = emptyList()
)

object HtmlSecurityReportExporterV1 {
    fun export(report: SecurityReportV1): String = buildString {
        append("<!doctype html><html lang=\"fa\" dir=\"rtl\"><head><meta charset=\"utf-8\">")
        append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>")
        append(escape(report.product)).append(" security report</title>")
        append("<style>body{font-family:Arial,sans-serif;background:#090a0d;color:#f4f5f7;margin:24px;line-height:1.7}section{background:#15171d;border-radius:14px;padding:16px;margin:14px 0}h1,h2{color:#e32645}small,.muted{color:#9aa0aa}.finding{border-top:1px solid #343843;padding:12px 0}.tag{color:#ffb45e}</style></head><body>")
        append("<h1>").append(escape(report.product)).append(" v").append(escape(report.version)).append("</h1>")
        append("<p class=\"muted\">زمان تولید: ").append(report.generatedAtEpochMs).append(" • شناسه مجوز: ").append(escape(report.authorizationId)).append("</p>")
        append("<section><h2>محدوده و روش</h2><p>").append(escape(report.scopeDescription)).append("</p><p>")
            .append(escape(report.methodology)).append("</p></section>")
        append("<section><h2>پوشش آزمون</h2><p>مخرج: ").append(report.coverage.denominator)
            .append(" • اجراشده: ").append(report.coverage.executed).append(" • ردشده: ").append(report.coverage.skipped)
            .append(" • مسدود: ").append(report.coverage.blocked).append(" • ناموفق: ").append(report.coverage.failed)
            .append(" • پوشش اجرا: ").append(String.format(Locale.US, "%.1f%%", report.coverage.coveragePercent)).append("</p></section>")
        append("<section><h2>یافته‌ها (").append(report.findings.size).append(")</h2>")
        report.findings.forEach { finding ->
            append("<div class=\"finding\"><h3>").append(escape(finding.title)).append("</h3><p class=\"tag\">")
                .append(escape(finding.severity.name)).append(" • ").append(escape(finding.status.name)).append("</p><p>")
                .append(escape(finding.description)).append("</p><p>دارایی: ").append(escape(finding.affectedAsset))
                .append(" • محل: ").append(escape(finding.exactLocation)).append("</p><p>شواهد: ")
                .append(escape(EvidenceSanitizer.sanitize(finding.evidence))).append("</p><p>اصلاح: ")
                .append(escape(finding.remediation)).append("</p></div>")
        }
        append("</section><section><h2>شواهد</h2><ul>")
        report.evidenceReferences.forEach { append("<li>").append(escape(it)).append("</li>") }
        append("</ul><h2>اصلاح و بازآزمایی</h2><ul>")
        report.remediationSummary.forEach { append("<li>").append(escape(it)).append("</li>") }
        append("</ul><p>").append(escape(report.retestSummary)).append("</p></section>")
        if (report.websiteSpecialistCoverage.isNotEmpty() || report.architectureRelationships.isNotEmpty()) {
            append("<section><h2>Website Security Specialist v2.0</h2><h3>Coverage</h3><ul>")
            report.websiteSpecialistCoverage.forEach { append("<li>").append(escape(it)).append("</li>") }
            append("</ul><h3>Architecture relationships</h3><ul>")
            report.architectureRelationships.forEach { append("<li>").append(escape(it)).append("</li>") }
            append("</ul><h3>Test plans</h3><ul>")
            report.websiteTestPlans.forEach { append("<li>").append(escape(it)).append("</li>") }
            append("</ul><h3>Evidence records</h3><ul>")
            report.websiteEvidenceRecords.forEach { append("<li>").append(escape(it)).append("</li>") }
            append("</ul><p class=\"muted\">Coverage status does not convert missing findings into PASS; observed and inferred relationships remain distinct. Evidence records contain sanitized fields only.</p></section>")
        }
        append("<section><h2>محدودیت‌ها</h2><ul>")
        report.limitations.forEach { append("<li>").append(escape(it)).append("</li>") }
        append("</ul><p class=\"muted\">نبود یافته به معنی امنیت کامل نیست. وضعیت‌ها و پوشش فقط به آزمون‌های ثبت‌شده مربوط‌اند.</p></section>")
        append("</body></html>")
    }

    /** HTML-escapes untrusted text (for example URLs discovered on a target site) before it is placed in a report. */
    fun escapeHtml(value: String): String = escape(value)

    private fun escape(value: String): String = value.replace("&", "&amp;")
        .replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;")
}
