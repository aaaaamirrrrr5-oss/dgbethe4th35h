package com.siteguard.app.core

/**
 * Explainable evidence-quality assessment. This is not exploitability or CVSS and
 * never upgrades a finding's underlying verification status.
 */
data class EvidenceConfidenceAssessmentV1(
    val score: Int,
    val band: String,
    val factors: List<String>,
    val caveat: String = "امتیاز کیفیت شواهد است؛ اثبات آسیب‌پذیری یا احتمال بهره‌برداری نیست."
)

object EvidenceConfidenceEngineV1 {
    fun assess(finding: Finding): EvidenceConfidenceAssessmentV1 {
        var score = when (finding.status) {
            FindingStatus.CONFIRMED -> 45
            FindingStatus.PROBABLE -> 30
            FindingStatus.UNVERIFIED -> 15
            FindingStatus.INFORMATIONAL -> 20
            FindingStatus.FALSE_POSITIVE -> 0
        }
        val factors = mutableListOf<String>()
        when (finding.status) {
            FindingStatus.CONFIRMED -> factors += "وضعیت منبع: تأییدشده (برچسب ثبت‌شده)"
            FindingStatus.PROBABLE -> factors += "وضعیت منبع: محتمل"
            FindingStatus.UNVERIFIED -> factors += "وضعیت منبع: تأییدنشده"
            FindingStatus.INFORMATIONAL -> factors += "یافته اطلاعاتی است"
            FindingStatus.FALSE_POSITIVE -> factors += "یافته به‌عنوان مثبت کاذب علامت‌گذاری شده است"
        }
        if (finding.evidence.isNotBlank()) { score += 15; factors += "شاهد متنی ثبت شده است" }
        else factors += "شاهد متنی قابل ارزیابی موجود نیست"
        if (finding.exactLocation.isNotBlank()) { score += 10; factors += "موقعیت دقیق ثبت شده است" }
        else factors += "موقعیت دقیق ثبت نشده است"
        val method = finding.detectionMethod.lowercase()
        if (method.contains("deterministic") || method.contains("static") || method.contains("direct") || method.contains("http")) {
            score += 10; factors += "روش تشخیص مشخص و قابل بازبینی است"
        } else factors += "روش تشخیص نیازمند توضیح بیشتر است"
        if (finding.evidence.length >= 80) { score += 10; factors += "شاهد جزئیات بیشتری دارد" }
        if (finding.confidence.equals("low", true)) { score -= 15; factors += "اعتماد اولیه پایین گزارش شده است" }
        if (finding.status == FindingStatus.FALSE_POSITIVE) score = 0
        score = score.coerceIn(0, 100)
        val band = when {
            score >= 75 -> "قوی"
            score >= 50 -> "متوسط"
            score >= 25 -> "محدود"
            else -> "ضعیف"
        }
        return EvidenceConfidenceAssessmentV1(score, band, factors)
    }
}
