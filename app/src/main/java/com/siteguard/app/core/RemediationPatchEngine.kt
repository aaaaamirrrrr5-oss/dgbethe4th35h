package com.siteguard.app.core

import java.security.MessageDigest
import java.util.UUID

enum class RemediationLifecycle { DRAFT, REVIEWED, APPROVED_FOR_STAGING, PATCH_PREVIEWED, TESTED, ACCEPTED, ROLLED_BACK }

data class PatchPreviewV1(
    val patchId: String,
    val sourcePath: String,
    val sourceSha256: String,
    val originalSnippetSha256: String,
    val before: String,
    val after: String,
    val unifiedDiff: String,
    val changesExactlyOneOccurrence: Boolean,
    val productionApplyAvailable: Boolean = false,
    val note: String = "پیش‌نمایش فقط روی متن ارائه‌شده تولید شده است؛ هیچ فایل یا سامانه‌ای تغییر نکرده است."
)

data class PatchPreviewResult(val preview: PatchPreviewV1?, val blockers: List<String>)

data class RemediationCaseV1(
    val caseId: String = UUID.randomUUID().toString(),
    val findingId: String,
    val affectedAsset: String,
    val affectedVersion: String,
    val exactLocation: String,
    val rootCause: String,
    val currentBehavior: String,
    val expectedBehavior: String,
    val recommendedChange: String,
    val compatibilityRisks: List<String>,
    val backupPlan: String,
    val rollbackPlan: String,
    val verification: String,
    val residualRisk: String,
    val lifecycle: RemediationLifecycle = RemediationLifecycle.DRAFT,
    val patchPreview: PatchPreviewV1? = null,
    val approvalNote: String = "",
    val playbookSection: String = "WP-14",
    val playbookTitle: String = "Patch Acceptance and Release",
    val rootCausePattern: String = "علت ریشه‌ای دقیق نیازمند تطبیق با source/config واقعی است.",
    val immediateContainment: String = "اقدام فوری فقط پس از ارزیابی ریسک و تأیید مالک؛ هیچ تغییری خودکار اعمال نمی‌شود.",
    val permanentFixPlan: String = "نسخه، framework، محل دقیق و مسیر داده/مجوز باید با سورس واقعی بررسی شود.",
    val regressionTests: List<String> = emptyList(),
    val stagingValidation: String = "روی staging و داده مصنوعی اجرا شود؛ production جداگانه تأیید می‌شود.",
    val deploymentMonitoring: String = "پس از انتشار، خطاها و رفتار حیاتی سامانه با معیار rollback پایش شوند.",
    val downtimeRisk: String = "پیش از تغییر، اثر migration و downtime بررسی شود.",
    val ownerRole: String = "Developer / asset owner",
    val patchApplicability: String = "CONCEPTUAL_ONLY: context واقعی source و نسخه framework برای patch ارائه نشده است.",
    val acceptanceChecklist: List<String> = listOf("Finding و root cause تأیید شود", "diff و compatibility review", "backup/rollback", "unit/integration/security tests", "staging validation", "production approval جداگانه", "post-deploy monitoring")
)

object RemediationPatchEngineV1 {
    fun createPlan(
        finding: Finding,
        affectedVersion: String = "نامشخص",
        exactLocation: String = finding.exactLocation,
        rootCause: String = finding.description,
        compatibilityRisks: List<String> = listOf("نسخه framework/plugin و سازگاری وابستگی‌ها باید پیش از انتشار بررسی شود.")
    ): RemediationCaseV1 {
        val guidance = WebsiteRemediationPlaybookV1.resolve(finding)
        return RemediationCaseV1(
        findingId = finding.id,
        affectedAsset = finding.affectedAsset,
        affectedVersion = affectedVersion,
        exactLocation = exactLocation,
        rootCause = rootCause,
        currentBehavior = finding.description,
        expectedBehavior = "رفتار مورد انتظار باید با کنترل امنیتی توصیه‌شده و بدون تغییر ناخواسته در منطق کسب‌وکار منطبق باشد.",
        recommendedChange = finding.remediation,
        compatibilityRisks = compatibilityRisks,
        backupPlan = "از فایل/تنظیم دقیق و نسخه فعلی پشتیبان بگیرید؛ restore backup را در staging تمرین کنید.",
        rollbackPlan = guidance.rollback,
        verification = listOf(finding.verificationProcedure, guidance.verification).filter { it.isNotBlank() }.distinct().joinToString("\n"),
        residualRisk = finding.notTested,
        playbookSection = guidance.sectionId,
        playbookTitle = guidance.sectionTitle,
        rootCausePattern = guidance.rootCausePattern,
        immediateContainment = guidance.immediateContainment,
        permanentFixPlan = guidance.permanentFix,
        regressionTests = guidance.regressionTests,
        stagingValidation = guidance.stagingValidation,
        deploymentMonitoring = guidance.deploymentMonitoring,
        downtimeRisk = guidance.downtimeRisk,
        ownerRole = guidance.ownerRole,
        patchApplicability = guidance.applicability
        )
    }

    /** Creates a diff only if the exact old snippet appears once in the exact supplied source. */
    fun previewPatch(
        sourcePath: String,
        sourceText: String,
        exactOldSnippet: String,
        replacement: String
    ): PatchPreviewResult {
        val blockers = mutableListOf<String>()
        if (sourcePath.isBlank() || sourcePath.startsWith("/") || sourcePath.contains('\\') || sourcePath.contains('\u0000') ||
            Regex("^[A-Za-z]:").containsMatchIn(sourcePath) || sourcePath.split('/').any { it == ".." || it == "." } ||
            Regex("(?i)%2e|%2f|%5c").containsMatchIn(sourcePath)) {
            blockers += "مسیر باید نسبی، portable و بدون traversal یا drive prefix باشد."
        }
        if (exactOldSnippet.isBlank()) blockers += "قطعه اصلی دقیق ارائه نشده است."
        if (replacement.isBlank()) blockers += "جایگزین خالی است؛ حذف کامل خودکار پشتیبانی نمی‌شود."
        if (sourceText.length > 1_000_000) blockers += "متن منبع از سقف یک مگابایت عبور کرده است."
        if (blockers.isNotEmpty()) return PatchPreviewResult(null, blockers)
        val first = sourceText.indexOf(exactOldSnippet)
        if (first < 0) return PatchPreviewResult(null, listOf("قطعه دقیق در فایل ارائه‌شده پیدا نشد؛ مسیر یا کد حدس زده نمی‌شود."))
        if (sourceText.indexOf(exactOldSnippet, first + exactOldSnippet.length) >= 0) {
            return PatchPreviewResult(null, listOf("قطعه اصلی بیش از یک بار وجود دارد؛ اصلاح خودکار مبهم است."))
        }
        val updated = sourceText.replaceRange(first, first + exactOldSnippet.length, replacement)
        val patch = PatchPreviewV1(
            patchId = UUID.randomUUID().toString(), sourcePath = sourcePath,
            sourceSha256 = sha256(sourceText.toByteArray(Charsets.UTF_8)),
            originalSnippetSha256 = sha256(exactOldSnippet.toByteArray(Charsets.UTF_8)),
            before = exactOldSnippet, after = replacement,
            unifiedDiff = buildString {
                append("--- a/").append(sourcePath).append('\n')
                append("+++ b/").append(sourcePath).append('\n')
                append("@@ exact-snippet @@\n")
                exactOldSnippet.lineSequence().forEach { append('-').append(it).append('\n') }
                replacement.lineSequence().forEach { append('+').append(it).append('\n') }
            },
            changesExactlyOneOccurrence = true
        )
        check(updated != sourceText)
        return PatchPreviewResult(patch, emptyList())
    }

    fun advance(case: RemediationCaseV1, next: RemediationLifecycle, explicitApproval: Boolean = false, evidence: String = ""): RemediationCaseV1 {
        val allowed = when (case.lifecycle) {
            RemediationLifecycle.DRAFT -> next == RemediationLifecycle.REVIEWED
            RemediationLifecycle.REVIEWED -> next == RemediationLifecycle.APPROVED_FOR_STAGING
            RemediationLifecycle.APPROVED_FOR_STAGING -> next == RemediationLifecycle.PATCH_PREVIEWED
            RemediationLifecycle.PATCH_PREVIEWED -> next == RemediationLifecycle.TESTED
            RemediationLifecycle.TESTED -> next == RemediationLifecycle.ACCEPTED || next == RemediationLifecycle.ROLLED_BACK
            RemediationLifecycle.ACCEPTED, RemediationLifecycle.ROLLED_BACK -> false
        }
        require(allowed) { "گذار اصلاح مجاز نیست: ${case.lifecycle} → $next" }
        when (next) {
            RemediationLifecycle.APPROVED_FOR_STAGING -> require(explicitApproval && evidence.isNotBlank()) { "تأیید انسانی و یادداشت محدوده staging لازم است." }
            RemediationLifecycle.PATCH_PREVIEWED -> require(case.patchPreview != null) { "پیش‌نمایش diff دقیق لازم است." }
            RemediationLifecycle.TESTED -> require(evidence.isNotBlank()) { "نتیجه واقعی regression test لازم است." }
            RemediationLifecycle.ACCEPTED -> require(explicitApproval && evidence.isNotBlank()) { "تأیید نهایی و evidence آزمون لازم است." }
            RemediationLifecycle.ROLLED_BACK -> require(evidence.isNotBlank()) { "مدرک rollback لازم است." }
            else -> Unit
        }
        return case.copy(lifecycle = next, approvalNote = if (evidence.isNotBlank()) evidence else case.approvalNote)
    }

    fun attachPreview(case: RemediationCaseV1, preview: PatchPreviewV1): RemediationCaseV1 {
        require(case.lifecycle == RemediationLifecycle.APPROVED_FOR_STAGING) { "ابتدا اصلاح باید برای staging تأیید شود." }
        require(preview.productionApplyAvailable.not())
        return case.copy(patchPreview = preview, patchApplicability = "EXACT_SNIPPET_PREVIEW_ONLY: فقط diff روی متن دقیق ارائه‌شده؛ اعمال فایل/production انجام نشده است.")
    }

    fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it) }
}
