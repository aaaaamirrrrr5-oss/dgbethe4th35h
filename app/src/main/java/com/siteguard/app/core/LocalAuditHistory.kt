package com.siteguard.app.core

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/** Small, user-clearable local history. No target content or credentials are uploaded. */
class LocalAuditHistory(context: Context) {
    companion object {
        @Volatile private var sharedInstance: LocalAuditHistory? = null
        fun get(context: Context): LocalAuditHistory = sharedInstance ?: synchronized(this) {
            sharedInstance ?: LocalAuditHistory(context.applicationContext).also { sharedInstance = it }
        }
    }

    private val prefs = context.getSharedPreferences("siteguard_history_v1", Context.MODE_PRIVATE)
    private val key = "scan_records_encrypted"
    private val cipher = LocalDataCipher()

    @Synchronized
    fun add(result: ScanResult, manifest: AuthorizationManifest? = null) {
        val rows = readRows()
        val newest = JSONObject().apply {
            put("host", result.host)
            put("scanned_at", result.scannedAt)
            put("http_status", result.httpStatus ?: JSONObject.NULL)
            put("finding_count", result.findings.size)
            put("authorization_id", result.authorizationId)
            put("summary", result.message.take(500))
            put("report_json", JsonReportExporter.exportScan(result))
            put("authorization_manifest", manifest?.let { authorization -> JSONObject().apply {
                put("schema_version", authorization.schemaVersion)
                put("authorization_id", authorization.authorizationId)
                put("owner_declaration", authorization.ownerDeclaration)
                put("authorized_hosts", JSONArray(authorization.authorizedHosts))
                put("excluded_hosts", JSONArray(authorization.excludedHosts))
                put("allowed_ports", JSONArray(authorization.allowedPorts))
                put("allowed_path_prefixes", JSONArray(authorization.allowedPathPrefixes))
                put("excluded_paths", JSONArray(authorization.excludedPaths))
                put("allowed_methods", JSONArray(authorization.allowedMethods))
                put("allow_private_network", authorization.allowPrivateNetwork)
                put("valid_from", authorization.validFromEpochMs)
                put("valid_until", authorization.validUntilEpochMs)
                put("max_requests", authorization.maxRequests)
                put("requests_per_minute", authorization.requestsPerMinute)
                put("emergency_stop", authorization.emergencyStopDescription)
            } } ?: JSONObject.NULL)
        }
        // A fresh array is required: JSONArray.put(0, value) replaces the old first row.
        val ordered = JSONArray().put(newest)
        for (i in 0 until rows.length()) rows.optJSONObject(i)?.let(ordered::put)
        val capped = JSONArray()
        for (i in 0 until minOf(ordered.length(), 30)) ordered.optJSONObject(i)?.let(capped::put)
        // Bound the encrypted SharedPreferences value (large reports x 30 rows could reach many MB and slow every read/write).
        var packed = capped.toString()
        while (packed.length > 3_000_000 && capped.length() > 1) {
            capped.remove(capped.length() - 1)
            packed = capped.toString()
        }
        prefs.edit().putString(key, cipher.encrypt(packed)).apply()
    }

    @Synchronized fun latestSummary(): String? = readRows().optJSONObject(0)?.optString("summary")?.takeIf { it.isNotBlank() }

    @Synchronized fun getSummaries(): List<String> {
        val rows = readRows()
        return (0 until rows.length()).mapNotNull { index ->
            rows.optJSONObject(index)?.let { row ->
                val date = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm", java.util.Locale.getDefault())
                    .format(java.util.Date(row.optLong("scanned_at")))
                "${row.optString("host")} • ${row.optInt("finding_count")} یافته • $date"
            }
        }
    }

    @Synchronized fun reportAt(index: Int): String? = readRows().optJSONObject(index)?.optString("report_json")?.takeIf { it.isNotBlank() }

    @Synchronized fun clear() { prefs.edit().remove(key).apply() }

    private fun readRows(): JSONArray {
        val encrypted = prefs.getString(key, null) ?: return JSONArray()
        val decoded = cipher.decrypt(encrypted) ?: return JSONArray()
        return runCatching { JSONArray(decoded) }.getOrDefault(JSONArray())
    }
}
