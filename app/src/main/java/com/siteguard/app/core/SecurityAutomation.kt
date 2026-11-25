package com.siteguard.app.core

import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap


enum class ScheduledAssessmentStatus { QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED, PAUSED_AUTHORIZATION, BLOCKED_EMERGENCY_STOP }

data class ScheduledAssessmentV1(
    val id: String = UUID.randomUUID().toString(),
    val idempotencyKey: String,
    val targetUrl: String,
    val authorization: AuthorizationManifest,
    val scheduledAtEpochMs: Long,
    val testClass: String,
    val maxRetries: Int = 2,
    val retryCount: Int = 0,
    val status: ScheduledAssessmentStatus = ScheduledAssessmentStatus.QUEUED,
    val createdAtEpochMs: Long = System.currentTimeMillis(),
    val lastResult: String = "",
    val lastRunAtEpochMs: Long? = null
)

data class AutomationAuditEventV1(
    val taskId: String,
    val action: String,
    val atEpochMs: Long,
    val detail: String
)

data class AutomationQueueSnapshotV1(
    val tasks: List<ScheduledAssessmentV1>,
    val audit: List<AutomationAuditEventV1>,
    val emergencyStopped: Boolean,
    val maxQueueSize: Int,
    val note: String = "صف در ذخیره‌سازی محلی رمزگذاری‌شده نگه‌داری می‌شود؛ کارهای سررسیدشده هنگام اجرای foreground برنامه بررسی می‌شوند و اجرای دائمی در پس‌زمینه تضمین نمی‌شود."
)

/** Foreground/local bounded queue. It deliberately does not claim always-on monitoring. */
class LocalAssessmentSchedulerV1(
    private val maxQueueSize: Int = 64,
    private val maxConcurrent: Int = 1,
    initialSnapshot: AutomationQueueSnapshotV1? = null
) {
    private val lock = Any()
    private val tasks = linkedMapOf<String, ScheduledAssessmentV1>()
    private val audit = mutableListOf<AutomationAuditEventV1>()
    private var emergencyStopped = false
    private var runningCount = 0

    init {
        require(maxQueueSize in 1..512 && maxConcurrent in 1..4)
        if (initialSnapshot != null) {
            require(initialSnapshot.tasks.size <= maxQueueSize) { "صف بازیابی‌شده از ظرفیت مجاز بزرگ‌تر است." }
            initialSnapshot.tasks.forEach { task ->
                // A process may die mid-task. Re-queue it, but authorization is revalidated by claimDue.
                val recovered = if (task.status == ScheduledAssessmentStatus.RUNNING)
                    task.copy(status = ScheduledAssessmentStatus.QUEUED, lastResult = "فرایند قبلی پیش از ثبت نتیجه بسته شد؛ مجوز هنگام اجرای مجدد دوباره بررسی می‌شود.")
                else task
                tasks[recovered.id] = recovered
            }
            audit.addAll(initialSnapshot.audit.takeLast(1_000))
            emergencyStopped = initialSnapshot.emergencyStopped
            initialSnapshot.tasks.filter { it.status == ScheduledAssessmentStatus.RUNNING }.forEach { task ->
                record(task.id, "RECOVERED_AFTER_PROCESS_RESTART", System.currentTimeMillis(), "کار نیمه‌تمام به صف بازگشت؛ مجوز باید دوباره تأیید شود.")
            }
        }
    }

    fun enqueue(task: ScheduledAssessmentV1, nowEpochMs: Long = System.currentTimeMillis()): ScheduledAssessmentV1 = synchronized(lock) {
        check(!emergencyStopped) { "Emergency Stop فعال است؛ کار جدید پذیرفته نمی‌شود." }
        require(tasks.size < maxQueueSize) { "ظرفیت صف به سقف رسیده است." }
        require(task.idempotencyKey.isNotBlank() && task.testClass.isNotBlank())
        require(task.scheduledAtEpochMs >= nowEpochMs) { "زمان برنامه‌ریزی نمی‌تواند در گذشته باشد." }
        require(tasks.values.none { it.idempotencyKey == task.idempotencyKey && it.status !in terminalStatuses }) {
            "کار تکراری با همین idempotency key ثبت شده است."
        }
        val scope = ScopeEnforcer.validate(task.targetUrl, task.authorization, nowEpochMs)
        require(scope.allowed) { "مجوز هنگام ثبت معتبر نیست: ${scope.reason}" }
        tasks[task.id] = task
        record(task.id, "ENQUEUED", nowEpochMs, "مجوز ${task.authorization.authorizationId} تا ${task.authorization.validUntilEpochMs}")
        task
    }

    /** Claims only due jobs after rechecking authorization immediately before execution. */
    fun claimDue(nowEpochMs: Long = System.currentTimeMillis()): List<ScheduledAssessmentV1> = synchronized(lock) {
        if (emergencyStopped) return@synchronized emptyList()
        val slots = (maxConcurrent - runningCount).coerceAtLeast(0)
        val due = tasks.values.filter { it.status == ScheduledAssessmentStatus.QUEUED && it.scheduledAtEpochMs <= nowEpochMs }
        val claimed = mutableListOf<ScheduledAssessmentV1>()
        due.forEach { task ->
            if (claimed.size >= slots) return@forEach
            val decision = ScopeEnforcer.validate(task.targetUrl, task.authorization, nowEpochMs)
            if (!decision.allowed) {
                tasks[task.id] = task.copy(status = ScheduledAssessmentStatus.PAUSED_AUTHORIZATION, lastResult = decision.reason)
                record(task.id, "PAUSED_AUTHORIZATION", nowEpochMs, decision.reason)
            } else {
                val running = task.copy(status = ScheduledAssessmentStatus.RUNNING, lastRunAtEpochMs = nowEpochMs)
                tasks[task.id] = running
                runningCount++
                claimed += running
                record(task.id, "CLAIMED", nowEpochMs, "مجوز مجدداً بررسی شد؛ اجرای تست هنوز در اختیار caller است.")
            }
        }
        claimed
    }

    fun complete(taskId: String, success: Boolean, result: String, nowEpochMs: Long = System.currentTimeMillis()): ScheduledAssessmentV1 = synchronized(lock) {
        val task = requireNotNull(tasks[taskId]) { "کار پیدا نشد." }
        require(task.status == ScheduledAssessmentStatus.RUNNING)
        runningCount = (runningCount - 1).coerceAtLeast(0)
        val updated = task.copy(
            status = if (success) ScheduledAssessmentStatus.COMPLETED else ScheduledAssessmentStatus.FAILED,
            lastResult = EvidenceSanitizer.sanitize(result).take(1000)
        )
        tasks[taskId] = updated
        record(taskId, if (success) "COMPLETED" else "FAILED", nowEpochMs, updated.lastResult)
        updated
    }

    fun retry(taskId: String, nextRunEpochMs: Long, nowEpochMs: Long = System.currentTimeMillis()): ScheduledAssessmentV1 = synchronized(lock) {
        val task = requireNotNull(tasks[taskId])
        require(task.status == ScheduledAssessmentStatus.FAILED && task.retryCount < task.maxRetries)
        require(nextRunEpochMs > nowEpochMs)
        val decision = ScopeEnforcer.validate(task.targetUrl, task.authorization, nowEpochMs)
        if (!decision.allowed) {
            val paused = task.copy(status = ScheduledAssessmentStatus.PAUSED_AUTHORIZATION, lastResult = decision.reason)
            tasks[taskId] = paused
            record(taskId, "PAUSED_AUTHORIZATION", nowEpochMs, decision.reason)
            return@synchronized paused
        }
        val updated = task.copy(status = ScheduledAssessmentStatus.QUEUED, retryCount = task.retryCount + 1, scheduledAtEpochMs = nextRunEpochMs)
        tasks[taskId] = updated
        record(taskId, "RETRY_SCHEDULED", nowEpochMs, "retry=${updated.retryCount}")
        updated
    }

    fun cancel(taskId: String, nowEpochMs: Long = System.currentTimeMillis()): Boolean = synchronized(lock) {
        val task = tasks[taskId] ?: return@synchronized false
        if (task.status in terminalStatuses) return@synchronized false
        if (task.status == ScheduledAssessmentStatus.RUNNING) runningCount = (runningCount - 1).coerceAtLeast(0)
        tasks[taskId] = task.copy(status = ScheduledAssessmentStatus.CANCELLED, lastResult = "لغو توسط کاربر")
        record(taskId, "CANCELLED", nowEpochMs, "لغو کار و جلوگیری از claim مجدد")
        true
    }

    fun emergencyStop(nowEpochMs: Long = System.currentTimeMillis()) = synchronized(lock) {
        emergencyStopped = true
        tasks.values.toList().forEach { task ->
            if (task.status == ScheduledAssessmentStatus.QUEUED) {
                tasks[task.id] = task.copy(status = ScheduledAssessmentStatus.BLOCKED_EMERGENCY_STOP)
                record(task.id, "BLOCKED_EMERGENCY_STOP", nowEpochMs, "Emergency Stop؛ کار صف‌شده claim نخواهد شد.")
            }
            if (task.status == ScheduledAssessmentStatus.RUNNING) {
                record(task.id, "STOP_REQUESTED", nowEpochMs, "لغو همکاری‌کننده لازم است؛ caller باید cancellation واقعی را اعمال کند.")
            }
        }
    }

    fun resetEmergencyStop(nowEpochMs: Long = System.currentTimeMillis()) = synchronized(lock) {
        emergencyStopped = false
        tasks.values.filter { it.status == ScheduledAssessmentStatus.BLOCKED_EMERGENCY_STOP }.forEach { task ->
            tasks[task.id] = task.copy(status = ScheduledAssessmentStatus.QUEUED)
            record(task.id, "REQUEUED_AFTER_REVIEW", nowEpochMs, "پس از بازبینی دستی دوباره در صف قرار گرفت.")
        }
    }

    fun snapshot(): AutomationQueueSnapshotV1 = synchronized(lock) {
        AutomationQueueSnapshotV1(tasks.values.toList(), audit.toList(), emergencyStopped, maxQueueSize)
    }

    private fun record(id: String, action: String, time: Long, detail: String) {
        audit += AutomationAuditEventV1(id, action, time, detail)
        if (audit.size > 1000) audit.removeAt(0)
    }

    companion object {
        private val terminalStatuses = setOf(ScheduledAssessmentStatus.COMPLETED, ScheduledAssessmentStatus.CANCELLED)
    }
}

data class AssetSnapshotV1(val assetId: String, val canonicalFacts: Map<String, String>, val capturedAtEpochMs: Long)
data class AssetDriftV1(val assetId: String, val previousHash: String, val currentHash: String, val changed: Boolean, val changedKeys: List<String>)

object AssetDriftDetectorV1 {
    fun fingerprint(snapshot: AssetSnapshotV1): String {
        val canonical = snapshot.canonicalFacts.toSortedMap().entries.joinToString("\n") { "${it.key}=${it.value}" }
        return MessageDigest.getInstance("SHA-256").digest(canonical.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
    fun compare(previous: AssetSnapshotV1, current: AssetSnapshotV1): AssetDriftV1 {
        require(previous.assetId == current.assetId)
        val oldHash = fingerprint(previous)
        val newHash = fingerprint(current)
        val keys = (previous.canonicalFacts.keys + current.canonicalFacts.keys).toSortedSet()
        val changed = keys.filter { previous.canonicalFacts[it] != current.canonicalFacts[it] }
        return AssetDriftV1(previous.assetId, oldHash, newHash, oldHash != newHash, changed)
    }
}
