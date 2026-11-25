package com.siteguard.app.core

data class RootCauseGroup(val cwe: String, val count: Int, val titles: List<String>, val suggestedFocus: String)

/**
 * Correlates findings by weakness class. Correlation is a triage hint,
 * not proof that findings share one underlying defect.
 */
object RootCauseAnalyzer {
    fun group(findings: List<Finding>): List<RootCauseGroup> =
        findings.filter { it.cwe.isNotBlank() }
            .groupBy { it.cwe }
            .map { (cwe, items) ->
                RootCauseGroup(
                    cwe = cwe,
                    count = items.size,
                    titles = items.map { it.title }.distinct().take(5),
                    suggestedFocus = when (cwe) {
                        "CWE-89" -> "مسیر داده از ورودی تا query و استفاده از پارامترهای bind شده را بررسی کنید."
                        "CWE-78" -> "تمام مسیرهای ورودی به اجرای فرایند و نحوه آرگومان‌بندی را بررسی کنید."
                        "CWE-79" -> "منبع داده و context خروجی در DOM را بررسی و encoding مناسب اعمال کنید."
                        "CWE-502" -> "مرز اعتماد و تمام نقاط deserialize را بررسی کنید."
                        "CWE-798" -> "منشأ credential، تاریخچه Git و امکان rotate کردن کلید را بررسی کنید."
                        else -> "یافته‌های هم‌کلاس را در یک بازبینی ریشه‌ای بررسی کنید."
                    }
                )
            }.sortedByDescending { it.count }
}
