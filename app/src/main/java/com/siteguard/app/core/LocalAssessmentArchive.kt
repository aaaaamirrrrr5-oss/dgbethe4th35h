package com.siteguard.app.core

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/** Encrypted local archive for website, source-file and project-ZIP assessments. */
data class ArchivedAssessmentV1(
    val id: String,
    val kind: String,
    val title: String,
    val target: String,
    val findingCount: Int,
    val savedAtEpochMs: Long,
    val reportJson: String
)

class LocalAssessmentArchive(context: Context, private val maxEntries: Int = 30) {
    companion object {
        @Volatile private var sharedInstance: LocalAssessmentArchive? = null
        fun get(context: Context): LocalAssessmentArchive = sharedInstance ?: synchronized(this) {
            sharedInstance ?: LocalAssessmentArchive(context.applicationContext).also { sharedInstance = it }
        }
    }

    private val prefs = context.getSharedPreferences("siteguard_assessment_archive_v1", Context.MODE_PRIVATE)
    private val cipher = LocalDataCipher("siteguard.assessment.archive.v1")
    private val key = "entries_encrypted"

    init { require(maxEntries in 1..100) }

    @Synchronized
    fun add(kind: String, title: String, target: String, findingCount: Int, reportJson: String, nowEpochMs: Long = System.currentTimeMillis()) {
        require(kind in setOf("website", "source", "project", "dns"))
        require(reportJson.length <= 600_000) { "گزارش برای ذخیره محلی بیش از حد بزرگ است." }
        val rows = readRows()
        // JSONArray.put(index, value) replaces an element; it does not prepend.
        // Build a fresh array so the newest assessment is always first without
        // silently overwriting the previous newest record.
        val newest = JSONObject().apply {
            put("id", java.util.UUID.randomUUID().toString())
            put("kind", kind)
            put("title", EvidenceSanitizer.sanitize(title).take(300))
            put("target", EvidenceSanitizer.sanitize(target).take(500))
            put("finding_count", findingCount.coerceAtLeast(0))
            put("saved_at", nowEpochMs)
            put("report", reportJson)
        }
        val combined = JSONArray().put(newest)
        for (index in 0 until rows.length()) {
            rows.optJSONObject(index)?.let(combined::put)
        }
        val rowsInOrder = combined
        val retained = (0 until minOf(rowsInOrder.length(), maxEntries)).mapNotNull { rowsInOrder.optJSONObject(it) }.toMutableList()
        var packed = JSONArray(retained).toString()
        while (packed.length > 3_000_000 && retained.size > 1) {
            retained.removeAt(retained.lastIndex)
            packed = JSONArray(retained).toString()
        }
        require(packed.length <= 3_000_000) { "گزارش جدید به‌تنهایی از سقف تاریخچه محلی بزرگ‌تر است." }
        prefs.edit().putString(key, cipher.encrypt(packed)).apply()
    }

    @Synchronized
    fun entries(): List<ArchivedAssessmentV1> {
        val rows = readRows()
        return (0 until rows.length()).mapNotNull { index -> rows.optJSONObject(index)?.let { row ->
            ArchivedAssessmentV1(
                row.optString("id"), row.optString("kind"), row.optString("title"),
                row.optString("target"), row.optInt("finding_count"), row.optLong("saved_at"), row.optString("report")
            )
        } }
    }

    @Synchronized fun reportAt(index: Int): String? = entries().getOrNull(index)?.reportJson
    @Synchronized fun clear() { prefs.edit().remove(key).apply() }

    private fun readRows(): JSONArray {
        val encrypted = prefs.getString(key, null) ?: return JSONArray()
        val decoded = cipher.decrypt(encrypted) ?: return JSONArray()
        return runCatching { JSONArray(decoded) }.getOrDefault(JSONArray())
    }
}
