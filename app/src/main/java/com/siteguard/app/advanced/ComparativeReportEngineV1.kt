package com.siteguard.app.advanced

import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

/** Stable snapshot comparison for reports; findings are matched by ID + canonical asset + location. */
data class ReportSnapshotFindingV1(val id: String, val severity: String, val asset: String, val location: String, val title: String, val evidenceHash: String)
data class ReportChangeV1(val kind: String, val key: String, val before: ReportSnapshotFindingV1?, val after: ReportSnapshotFindingV1?)
data class ComparativeReportV1(
    val generatedAtEpochMs: Long, val previousAtEpochMs: Long?, val currentAtEpochMs: Long,
    val newFindings: Int, val resolvedFindings: Int, val changedFindings: Int, val unchangedFindings: Int,
    val changes: List<ReportChangeV1>, val summary: String, val limitations: List<String>
)

object ComparativeReportEngineV1 {
    fun evidenceFingerprint(value: String): String = java.security.MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }

    fun compare(previous: List<ReportSnapshotFindingV1>?, current: List<ReportSnapshotFindingV1>, previousAt: Long? = null,
                currentAt: Long = System.currentTimeMillis(), now: Long = System.currentTimeMillis()): ComparativeReportV1 {
        require(current.size <= 5_000 && (previous?.size ?: 0) <= 5_000)
        fun key(f: ReportSnapshotFindingV1) = listOf(f.id.trim(), f.asset.trim().lowercase(), f.location.trim()).joinToString("|")
        val oldMap = (previous ?: emptyList()).associateBy(::key)
        val newMap = current.associateBy(::key)
        val keys = (oldMap.keys + newMap.keys).toSortedSet()
        val changes = keys.mapNotNull { k ->
            val old = oldMap[k]; val fresh = newMap[k]
            when {
                old == null -> ReportChangeV1("NEW", k, null, fresh)
                fresh == null -> ReportChangeV1("RESOLVED", k, old, null)
                old.severity != fresh.severity || old.evidenceHash != fresh.evidenceHash || old.title != fresh.title -> ReportChangeV1("CHANGED", k, old, fresh)
                else -> null
            }
        }
        val newCount = changes.count { it.kind == "NEW" }
        val resolved = changes.count { it.kind == "RESOLVED" }
        val changed = changes.count { it.kind == "CHANGED" }
        val unchanged = (current.size - newCount - changed).coerceAtLeast(0)
        val summary = if (previous == null) "اولین snapshot ثبت شد: ${current.size} یافته؛ مقایسه تاریخی در اجرای بعدی فعال می‌شود."
        else "${newCount} یافته جدید، ${resolved} مورد رفع‌شده، ${changed} مورد تغییرکرده و ${unchanged} مورد بدون تغییر."
        return ComparativeReportV1(now, previousAt, currentAt, newCount, resolved, changed, unchanged, changes, summary,
            listOf("رفع‌شدن فقط به معنی دیده‌نشدن همان کلید در snapshot جدید است؛ remediation یا رفع واقعی باید جداگانه retest شود.",
                "تغییر fingerprint ممکن است ناشی از تغییر متن شواهد یا نسخه اسکنر باشد.",
                "مقایسه فقط بین مجموعه ورودی انجام می‌شود و پوشش اسکن‌ها باید همسان باشد."))
    }

    fun toMarkdown(report: ComparativeReportV1): String = buildString {
        appendLine("# SiteGuard Comparative Security Report")
        appendLine("- Generated: ${iso(report.generatedAtEpochMs)}")
        appendLine("- Previous: ${report.previousAtEpochMs?.let(::iso) ?: "n/a"}")
        appendLine("- Current: ${iso(report.currentAtEpochMs)}")
        appendLine("- New: ${report.newFindings}; Resolved from scan: ${report.resolvedFindings}; Changed: ${report.changedFindings}; Unchanged: ${report.unchangedFindings}")
        appendLine(); appendLine(report.summary); appendLine(); appendLine("## Changes")
        report.changes.take(500).forEach { change ->
            val f = change.after ?: change.before
            appendLine("- **${change.kind}** ${f?.id.orEmpty()} — ${f?.title.orEmpty()} — ${f?.severity.orEmpty()} — ${f?.asset.orEmpty()} ${f?.location.orEmpty()}")
        }
        appendLine(); appendLine("## Limitations"); report.limitations.forEach { appendLine("- $it") }
    }

    private fun iso(time: Long) = DateTimeFormatter.ISO_OFFSET_DATE_TIME.format(Instant.ofEpochMilli(time).atZone(ZoneId.systemDefault()))
}
