package com.siteguard.app.core

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * Android Keystore-backed persistence adapter for the bounded scheduler.
 * WorkManager and the foreground UI share one process-wide instance and re-check scope on claim.
 */
class PersistentAssessmentQueueV1(context: Context, private val maxQueueSize: Int = 64) {
    companion object {
        @Volatile private var sharedInstance: PersistentAssessmentQueueV1? = null

        /** One process-wide scheduler instance is shared by Compose and WorkManager workers. */
        fun get(context: Context): PersistentAssessmentQueueV1 = sharedInstance ?: synchronized(this) {
            sharedInstance ?: PersistentAssessmentQueueV1(context.applicationContext).also { sharedInstance = it }
        }
    }

    private val prefs = context.getSharedPreferences("siteguard_automation_queue_v1", Context.MODE_PRIVATE)
    private val cipher = LocalDataCipher("siteguard.automation.queue.v1")
    private val key = "snapshot_encrypted"
    private val scheduler = LocalAssessmentSchedulerV1(maxQueueSize = maxQueueSize, initialSnapshot = readSnapshot())

    @Synchronized fun enqueue(task: ScheduledAssessmentV1): ScheduledAssessmentV1 = scheduler.enqueue(task).also { persist() }
    @Synchronized fun claimDue(nowEpochMs: Long = System.currentTimeMillis()): List<ScheduledAssessmentV1> = scheduler.claimDue(nowEpochMs).also { persist() }
    @Synchronized fun complete(taskId: String, success: Boolean, result: String, nowEpochMs: Long = System.currentTimeMillis()): ScheduledAssessmentV1 =
        scheduler.complete(taskId, success, result, nowEpochMs).also { persist() }
    @Synchronized fun retry(taskId: String, nextRunEpochMs: Long, nowEpochMs: Long = System.currentTimeMillis()): ScheduledAssessmentV1 =
        scheduler.retry(taskId, nextRunEpochMs, nowEpochMs).also { persist() }
    @Synchronized fun cancel(taskId: String, nowEpochMs: Long = System.currentTimeMillis()): Boolean = scheduler.cancel(taskId, nowEpochMs).also { persist() }
    @Synchronized fun emergencyStop(nowEpochMs: Long = System.currentTimeMillis()) { scheduler.emergencyStop(nowEpochMs); persist() }
    @Synchronized fun resetEmergencyStop(nowEpochMs: Long = System.currentTimeMillis()) { scheduler.resetEmergencyStop(nowEpochMs); persist() }
    @Synchronized fun snapshot(): AutomationQueueSnapshotV1 = scheduler.snapshot()
    @Synchronized fun clear() { prefs.edit().remove(key).apply() }

    private fun persist() {
        // commit() (not apply()) so a claimed/completed task state survives the OS killing the worker process right after.
        prefs.edit().putString(key, cipher.encrypt(encode(scheduler.snapshot()).toString())).commit()
    }

    private fun readSnapshot(): AutomationQueueSnapshotV1? {
        val encrypted = prefs.getString(key, null) ?: return null
        val plain = cipher.decrypt(encrypted) ?: return null
        return runCatching { decode(JSONObject(plain)) }.getOrNull()
    }

    private fun encode(snapshot: AutomationQueueSnapshotV1): JSONObject = JSONObject().apply {
        put("schema", 1)
        put("emergency_stopped", snapshot.emergencyStopped)
        put("tasks", JSONArray().apply { snapshot.tasks.forEach { task -> put(JSONObject().apply {
            put("id", task.id); put("idempotency_key", task.idempotencyKey); put("target_url", task.targetUrl)
            put("scheduled_at", task.scheduledAtEpochMs); put("test_class", task.testClass); put("max_retries", task.maxRetries)
            put("retry_count", task.retryCount); put("status", task.status.name); put("created_at", task.createdAtEpochMs)
            put("last_result", EvidenceSanitizer.sanitize(task.lastResult).take(1_000)); put("last_run_at", task.lastRunAtEpochMs ?: JSONObject.NULL)
            put("authorization", encodeManifest(task.authorization))
        }) } })
        put("audit", JSONArray().apply { snapshot.audit.takeLast(1_000).forEach { event -> put(JSONObject()
            .put("task_id", event.taskId).put("action", event.action).put("at", event.atEpochMs).put("detail", EvidenceSanitizer.sanitize(event.detail).take(1_000))) } })
    }

    private fun encodeManifest(manifest: AuthorizationManifest): JSONObject = JSONObject().apply {
        put("schema_version", manifest.schemaVersion); put("authorization_id", manifest.authorizationId)
        put("owner_declaration", manifest.ownerDeclaration); put("authorized_hosts", JSONArray(manifest.authorizedHosts))
        put("allowed_ports", JSONArray(manifest.allowedPorts)); put("allowed_paths", JSONArray(manifest.allowedPathPrefixes))
        put("excluded_paths", JSONArray(manifest.excludedPaths)); put("allowed_methods", JSONArray(manifest.allowedMethods))
        put("excluded_hosts", JSONArray(manifest.excludedHosts)); put("allow_private", manifest.allowPrivateNetwork)
        put("valid_from", manifest.validFromEpochMs); put("valid_until", manifest.validUntilEpochMs)
        put("max_requests", manifest.maxRequests); put("requests_per_minute", manifest.requestsPerMinute)
        put("emergency_stop_description", manifest.emergencyStopDescription)
    }

    private fun decode(root: JSONObject): AutomationQueueSnapshotV1 {
        require(root.optInt("schema") == 1)
        val tasksJson = root.optJSONArray("tasks") ?: JSONArray()
        require(tasksJson.length() <= maxQueueSize)
        // Each row is decoded in isolation: one corrupt/unknown row is dropped (fail closed) instead of discarding the
        // whole queue, and an unknown status is never silently turned into QUEUED (which could revive a cancelled task).
        val tasks = (0 until tasksJson.length()).mapNotNull { index -> tasksJson.optJSONObject(index)?.let { row -> runCatching {
            val auth = decodeManifest(row.getJSONObject("authorization"))
            ScheduledAssessmentV1(
                id = row.optString("id"), idempotencyKey = row.optString("idempotency_key"),
                targetUrl = row.optString("target_url"), authorization = auth,
                scheduledAtEpochMs = row.optLong("scheduled_at"), testClass = row.optString("test_class"),
                maxRetries = row.optInt("max_retries", 2), retryCount = row.optInt("retry_count"),
                status = ScheduledAssessmentStatus.valueOf(row.getString("status")),
                createdAtEpochMs = row.optLong("created_at"), lastResult = row.optString("last_result"),
                lastRunAtEpochMs = if (row.isNull("last_run_at")) null else row.optLong("last_run_at")
            )
        }.getOrNull() } }
        val auditJson = root.optJSONArray("audit") ?: JSONArray()
        val audit = (0 until auditJson.length()).mapNotNull { index -> auditJson.optJSONObject(index)?.let { row ->
            AutomationAuditEventV1(row.optString("task_id"), row.optString("action"), row.optLong("at"), row.optString("detail"))
        } }
        return AutomationQueueSnapshotV1(tasks, audit, root.optBoolean("emergency_stopped"), maxQueueSize)
    }

    private fun decodeManifest(row: JSONObject): AuthorizationManifest = AuthorizationManifest(
        schemaVersion = row.optInt("schema_version", 1), authorizationId = row.optString("authorization_id"),
        ownerDeclaration = row.optString("owner_declaration"), authorizedHosts = row.stringSet("authorized_hosts"),
        allowedPorts = row.intSet("allowed_ports"), allowedPathPrefixes = row.stringSet("allowed_paths"),
        excludedPaths = row.stringSet("excluded_paths"), allowedMethods = row.stringSet("allowed_methods"),
        excludedHosts = row.stringSet("excluded_hosts"), allowPrivateNetwork = row.optBoolean("allow_private"),
        validFromEpochMs = row.optLong("valid_from"), validUntilEpochMs = row.optLong("valid_until"),
        maxRequests = row.optInt("max_requests", 1), requestsPerMinute = row.optInt("requests_per_minute", 1),
        emergencyStopDescription = row.optString("emergency_stop_description")
    )

    private fun JSONObject.stringSet(key: String): Set<String> = (optJSONArray(key) ?: JSONArray()).let { array ->
        (0 until array.length()).mapNotNull { array.optString(it).takeIf(String::isNotBlank) }.toSet()
    }
    private fun JSONObject.intSet(key: String): Set<Int> = (optJSONArray(key) ?: JSONArray()).let { array ->
        (0 until array.length()).map { array.optInt(it) }.filter { it in 1..65_535 }.toSet()
    }
}
