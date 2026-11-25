package com.siteguard.app.core

data class TriagePriority(val score: Int, val band: String, val explanation: String)

/** A prioritization index only; it is not CVSS and must never be presented as a CVSS score. */
object RiskEngine {
    fun prioritize(finding: Finding): TriagePriority {
        val base = when (finding.severity) {
            Severity.CRITICAL -> 95
            Severity.HIGH -> 80
            Severity.MEDIUM -> 60
            Severity.LOW -> 35
            Severity.INFO -> 10
        }
        val confidenceFactor = when (finding.confidence.lowercase()) {
            "high" -> 1.0
            "medium", "low–medium" -> 0.8
            "low" -> 0.6
            else -> 0.7
        }
        val statusFactor = when (finding.status) {
            FindingStatus.CONFIRMED -> 1.0
            FindingStatus.PROBABLE -> 0.85
            FindingStatus.UNVERIFIED -> 0.7
            FindingStatus.INFORMATIONAL -> 0.5
            FindingStatus.FALSE_POSITIVE -> 0.0
        }
        val score = (base * confidenceFactor * statusFactor).toInt().coerceIn(0, 100)
        val band = when {
            score >= 80 -> "اولویت بسیار بالا"
            score >= 60 -> "اولویت بالا"
            score >= 35 -> "اولویت متوسط"
            score > 0 -> "اولویت پایین"
            else -> "بسته/ردشده"
        }
        return TriagePriority(score, band, "شاخص داخلی اولویت‌بندی بر اساس شدت، اطمینان و وضعیت؛ CVSS نیست.")
    }
}
