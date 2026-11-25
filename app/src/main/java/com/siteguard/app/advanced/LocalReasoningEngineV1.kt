package com.siteguard.app.advanced

import java.util.Locale

/** Evidence-led local decision support. This is deterministic inference, not a generative model. */
enum class LocalRiskV1 { CRITICAL, HIGH, MEDIUM, LOW, INFO }

data class LocalSecuritySignalV1(
    val id: String,
    val title: String,
    val severity: LocalRiskV1,
    val confidence: Int,
    val cwe: String = "",
    val asset: String = "",
    val evidence: String = "",
    val source: String = "local-analysis"
)

data class ReasoningStepV1(val ruleId: String, val explanation: String, val evidenceIds: List<String>)
data class PrioritizedActionV1(val priority: Int, val title: String, val why: String, val suggestedValidation: String, val linkedSignals: List<String>)
data class LocalReasoningReportV1(
    val generatedAtEpochMs: Long,
    val overallScore: Int,
    val priority: String,
    val steps: List<ReasoningStepV1>,
    val actions: List<PrioritizedActionV1>,
    val limitations: List<String>
)

object LocalReasoningEngineV1 {
    fun reason(signals: List<LocalSecuritySignalV1>, nowEpochMs: Long = System.currentTimeMillis()): LocalReasoningReportV1 {
        val bounded = signals.take(500).map { it.copy(
            id = it.id.take(96), title = it.title.take(240), evidence = it.evidence.take(1_000),
            asset = it.asset.take(512), confidence = it.confidence.coerceIn(0, 100)
        ) }
        val riskWeight = mapOf(
            LocalRiskV1.CRITICAL to 100, LocalRiskV1.HIGH to 75, LocalRiskV1.MEDIUM to 45,
            LocalRiskV1.LOW to 20, LocalRiskV1.INFO to 5
        )
        val weighted = bounded.map { it to (riskWeight.getValue(it.severity) * it.confidence / 100) }
        val base = weighted.maxOfOrNull { it.second } ?: 0
        val independent = bounded.map { it.source }.filter { it.isNotBlank() }.distinct().size
        val sameAssetCount = bounded.filter { it.severity in setOf(LocalRiskV1.CRITICAL, LocalRiskV1.HIGH) }
            .groupBy { it.asset.lowercase(Locale.ROOT).ifBlank { "unknown" } }.values.maxOfOrNull { it.size } ?: 0
        val corroboration = when {
            independent >= 3 -> 12
            independent == 2 -> 7
            else -> 0
        }
        val clustering = if (sameAssetCount >= 3) 8 else if (sameAssetCount == 2) 4 else 0
        val score = (base + corroboration + clustering).coerceIn(0, 100)
        val top = weighted.sortedByDescending { it.second }.take(8)
        val steps = mutableListOf<ReasoningStepV1>()
        if (top.isNotEmpty()) {
            steps += ReasoningStepV1("SG-RSN-001", "بالاترین ریسک بر اساس شدت و اطمینان شواهد انتخاب شد؛ شدت به‌تنهایی اثبات بهره‌پذیری نیست.", top.map { it.first.id })
        }
        if (independent > 1) {
            steps += ReasoningStepV1("SG-RSN-002", "یافته‌ها از $independent منبع تحلیلی مستقل آمده‌اند؛ این هم‌پوشانی اولویت بررسی را بالا می‌برد، اما به‌تنهایی رابطه علّی را ثابت نمی‌کند.", bounded.map { it.id }.distinct().take(20))
        }
        if (sameAssetCount > 1) {
            steps += ReasoningStepV1("SG-RSN-003", "چند نشانه پرریسک روی یک دارایی جمع شده‌اند؛ بررسی علت مشترک و مسیرهای وابسته پیشنهاد می‌شود.", bounded.filter { it.asset == top.firstOrNull()?.first?.asset }.map { it.id })
        }
        if (steps.isEmpty()) steps += ReasoningStepV1("SG-RSN-000", "شواهد کافی برای نتیجه‌گیری وجود ندارد؛ نبود یافته به معنی امن بودن سامانه نیست.", emptyList())

        val actions = top.mapIndexed { index, (signal, value) ->
            PrioritizedActionV1(
                priority = index + 1,
                title = when (signal.severity) {
                    LocalRiskV1.CRITICAL -> "مهار و بررسی فوری: ${signal.title}"
                    LocalRiskV1.HIGH -> "بازبینی اولویت‌دار: ${signal.title}"
                    else -> "اعتبارسنجی و برنامه اصلاح: ${signal.title}"
                },
                why = "شدت=${signal.severity}، اطمینان=${signal.confidence}%، امتیاز وزنی=$value؛ دارایی=${signal.asset.ifBlank { "نامشخص" }}",
                suggestedValidation = "شواهد اصلی را بازبینی کنید، در staging با ورودی بی‌خطر تکرار کنید و نتیجه مثبت/منفی را ثبت کنید.",
                linkedSignals = listOf(signal.id)
            )
        }
        return LocalReasoningReportV1(
            nowEpochMs, score,
            when { score >= 85 -> "بحرانی"; score >= 65 -> "بالا"; score >= 35 -> "متوسط"; score > 0 -> "پایین"; else -> "نامشخص" },
            steps, actions,
            listOf(
                "این موتور محلی و قاعده‌محور است؛ مدل زبانی یا یادگیری پارامتری در این نسخه وجود ندارد.",
                "امتیاز اولویت‌بندی است و احتمال compromise یا exploit را محاسبه نمی‌کند.",
                "برای نتیجه عملیاتی، نسخه محصول، محیط اجرا و مجوز بررسی باید جداگانه اعتبارسنجی شوند."
            )
        )
    }
}
