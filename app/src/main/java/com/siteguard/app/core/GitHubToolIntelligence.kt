package com.siteguard.app.core

import java.net.URI
import java.security.MessageDigest
import java.time.Instant

/** Metadata-only public-tool registry. It never downloads or executes repositories. */
enum class ToolLifecycle {
    DISCOVERED, REVIEWED, LAB_TESTED, APPROVED, INSTALLED, MONITORED, DEPRECATED, REMOVED
}

data class ToolAdapterDescriptor(
    val adapterId: String,
    val contractVersion: Int = 1,
    val capabilities: Set<String>,
    val supportedOs: Set<String>,
    val supportedAbis: Set<String> = emptySet(),
    val inputSchema: String,
    val outputSchema: String,
    val resourceNotes: String,
    val safetyLimits: List<String>,
    val cancellationSupported: Boolean
)

data class ToolCandidate(
    val id: String,
    val name: String,
    val repositoryUrl: String,
    val owner: String,
    val licenseId: String,
    val releaseTag: String,
    val commitSha: String,
    val sourceArchiveSha256: String,
    val lastCommitEpochMs: Long,
    val supportedOs: Set<String>,
    val supportedAbis: Set<String>,
    val dependenciesReviewed: Boolean = false,
    val installScriptsReviewed: Boolean = false,
    val binaryDownloadsReviewed: Boolean = false,
    val permissionsReviewed: Boolean = false,
    val networkBehaviorReviewed: Boolean = false,
    val vulnerabilitiesReviewed: Boolean = false,
    val licenseReviewed: Boolean = false,
    val signatureVerified: Boolean = false,
    val sandboxTestPassed: Boolean = false,
    val adapter: ToolAdapterDescriptor? = null,
    val lifecycle: ToolLifecycle = ToolLifecycle.DISCOVERED,
    val notes: String = ""
)

data class ToolReviewResult(val approved: Boolean, val blockers: List<String>, val normalizedRepository: String?)

object GitHubToolIntelligence {
    private val sha40 = Regex("^[a-fA-F0-9]{40}$")
    private val sha64 = Regex("^[a-fA-F0-9]{64}$")

    fun review(candidate: ToolCandidate): ToolReviewResult {
        val blockers = mutableListOf<String>()
        val repo = normalizeRepository(candidate.repositoryUrl)
        if (repo == null) blockers += "نشانی باید مخزن عمومی GitHub با مسیر owner/repository باشد."
        if (candidate.owner.isBlank()) blockers += "مالک مخزن مشخص نشده است."
        if (candidate.licenseId.isBlank() || !candidate.licenseReviewed) blockers += "مجوز نرم‌افزار هنوز بررسی نشده است."
        if (!sha40.matches(candidate.commitSha)) blockers += "شناسه commit باید SHA-1 چهل‌رقمی معتبر باشد."
        if (!sha64.matches(candidate.sourceArchiveSha256)) blockers += "هش آرشیو منبع باید SHA-256 شصت‌وچهاررقمی باشد."
        if (candidate.releaseTag.isBlank()) blockers += "نسخه/release باید pin شود."
        if (candidate.lastCommitEpochMs <= 0L) blockers += "تاریخ آخرین فعالیت مخزن ثبت نشده است."
        if (!candidate.dependenciesReviewed) blockers += "درخت وابستگی‌ها بررسی نشده است."
        if (!candidate.installScriptsReviewed) blockers += "اسکریپت‌های نصب/ساخت بررسی نشده‌اند."
        if (!candidate.binaryDownloadsReviewed) blockers += "دانلودهای باینری و منبع آن‌ها بررسی نشده‌اند."
        if (!candidate.permissionsReviewed) blockers += "مجوزها و قابلیت‌های موردنیاز بررسی نشده‌اند."
        if (!candidate.networkBehaviorReviewed) blockers += "رفتار شبکه بررسی نشده است."
        if (!candidate.vulnerabilitiesReviewed) blockers += "هشدارهای امنیتی و آسیب‌پذیری‌های شناخته‌شده بررسی نشده‌اند."
        return ToolReviewResult(blockers.isEmpty(), blockers, repo)
    }

    fun normalizeRepository(raw: String): String? = runCatching {
        val uri = URI(raw.trim())
        val parts = uri.path.trim('/').split('/')
        if (!uri.scheme.equals("https", true) || !uri.host.equals("github.com", true) ||
            uri.userInfo != null || parts.size != 2 || parts.any { it.isBlank() || it == "." || it == ".." }) return null
        "https://github.com/${parts[0]}/${parts[1].removeSuffix(".git")}".lowercase()
    }.getOrNull()

    fun transition(candidate: ToolCandidate, next: ToolLifecycle, explicitApproval: Boolean = false): ToolCandidate {
        val allowed = when (candidate.lifecycle) {
            ToolLifecycle.DISCOVERED -> next == ToolLifecycle.REVIEWED
            ToolLifecycle.REVIEWED -> next == ToolLifecycle.LAB_TESTED
            ToolLifecycle.LAB_TESTED -> next == ToolLifecycle.APPROVED
            ToolLifecycle.APPROVED -> next == ToolLifecycle.INSTALLED
            ToolLifecycle.INSTALLED -> next == ToolLifecycle.MONITORED
            ToolLifecycle.MONITORED -> next == ToolLifecycle.DEPRECATED || next == ToolLifecycle.REMOVED
            ToolLifecycle.DEPRECATED -> next == ToolLifecycle.REMOVED
            ToolLifecycle.REMOVED -> false
        }
        require(allowed) { "گذار چرخه عمر ابزار مجاز نیست: ${candidate.lifecycle} → $next" }
        when (next) {
            ToolLifecycle.REVIEWED -> require(review(candidate).approved) { review(candidate).blockers.joinToString(" ") }
            ToolLifecycle.LAB_TESTED -> require(candidate.adapter != null) { "قرارداد adapter باید پیش از تست آزمایشگاهی تعریف شود." }
            ToolLifecycle.APPROVED -> require(candidate.sandboxTestPassed && explicitApproval) { "تأیید انسانی و تست sandbox موفق لازم است." }
            ToolLifecycle.INSTALLED -> require(explicitApproval) { "نصب ابزار نیازمند تأیید صریح کاربر است." }
            ToolLifecycle.MONITORED -> require(candidate.lifecycle == ToolLifecycle.INSTALLED) { "ابزار نصب‌شده لازم است." }
            ToolLifecycle.DEPRECATED, ToolLifecycle.REMOVED -> Unit
            ToolLifecycle.DISCOVERED -> Unit
        }
        return candidate.copy(lifecycle = next)
    }

    fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it) }

    fun isFreshEnough(lastCommitEpochMs: Long, nowEpochMs: Long, maxAgeDays: Long): Boolean =
        lastCommitEpochMs > 0 && nowEpochMs >= lastCommitEpochMs &&
            nowEpochMs - lastCommitEpochMs <= maxAgeDays.coerceAtLeast(0) * 86_400_000L
}
