package com.siteguard.app.advanced

import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.time.LocalDate
import java.time.format.DateTimeParseException
import java.util.Locale
import javax.net.ssl.HttpsURLConnection

private const val CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

data class ThreatIntelEntryV1(
    val cveId: String,
    val vendor: String,
    val product: String,
    val name: String,
    val dateAdded: String,
    val description: String,
    val requiredAction: String,
    val dueDate: String,
    val ransomwareKnown: Boolean,
    val notes: String
)

data class ThreatIntelSnapshotV1(
    val catalogVersion: String,
    val dateReleased: String,
    val count: Int,
    val fetchedAtEpochMs: Long,
    val sha256: String,
    val entries: List<ThreatIntelEntryV1>,
    val source: String = CISA_KEV_URL
)

object CisaKevFeedParserV1 {
    fun parse(json: String, fetchedAtEpochMs: Long = System.currentTimeMillis()): ThreatIntelSnapshotV1 {
        val root = MiniJsonV1.objectValue(MiniJsonV1.parse(json, maxChars = 12_000_000, maxDepth = 24))
        val catalogVersion = root.string("catalogVersion", 80)
        val dateReleased = root.string("dateReleased", 10)
        runCatching { LocalDate.parse(dateReleased) }.getOrElse { throw IllegalArgumentException("CISA feed dateReleased is invalid") }
        val rows = MiniJsonV1.arrayValue(root["vulnerabilities"])
        require(rows.size <= 20_000) { "CISA catalog exceeds supported row count" }
        val entries = rows.mapNotNull { item ->
            val row = item as? Map<*, *> ?: return@mapNotNull null
            val cve = (row["cveID"] as? String)?.uppercase(Locale.ROOT)?.takeIf { Regex("CVE-\\d{4}-\\d{4,}").matches(it) }
                ?: return@mapNotNull null
            val added = (row["dateAdded"] as? String).orEmpty().take(10)
            if (added.isNotBlank()) runCatching { LocalDate.parse(added) }.getOrElse { return@mapNotNull null }
            ThreatIntelEntryV1(
                cve, (row["vendorProject"] as? String).orEmpty().clean(180),
                (row["product"] as? String).orEmpty().clean(180),
                (row["vulnerabilityName"] as? String).orEmpty().clean(240), added,
                (row["shortDescription"] as? String).orEmpty().clean(1_000),
                (row["requiredAction"] as? String).orEmpty().clean(1_000),
                (row["dueDate"] as? String).orEmpty().take(10).also { due ->
                    if (due.isNotBlank()) runCatching { LocalDate.parse(due) }.getOrElse { return@mapNotNull null }
                },
                (row["knownRansomwareCampaignUse"] as? String).equals("Known", true),
                (row["notes"] as? String).orEmpty().clean(1_000)
            )
        }.distinctBy { it.cveId }
        require(entries.isNotEmpty()) { "CISA feed contains no valid CVE records" }
        val declaredCount = (root["count"] as? Number)?.toInt() ?: throw IllegalArgumentException("CISA feed count is missing")
        require(declaredCount in 1..20_000 && declaredCount == rows.size) { "CISA feed count does not match vulnerabilities array" }
        val hash = sha256(json.toByteArray(Charsets.UTF_8))
        return ThreatIntelSnapshotV1(catalogVersion, dateReleased, entries.size, fetchedAtEpochMs, hash, entries)
    }

    private fun Map<String, Any?>.string(key: String, max: Int): String {
        val value = this[key] as? String ?: throw IllegalArgumentException("CISA feed missing $key")
        require(value.isNotBlank() && value.length <= max) { "Invalid CISA field $key" }
        return value
    }

    private fun String.clean(max: Int) = filter { it == '\n' || it == '\t' || it.code >= 0x20 }.take(max)
    private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}

/** Fetches only the fixed official CISA HTTPS feed; redirects and unbounded bodies are rejected. */
class CisaKevFeedUpdaterV1(
    private val connectTimeoutMs: Int = 12_000,
    private val readTimeoutMs: Int = 20_000,
    private val maxBytes: Int = 12 * 1024 * 1024
) {
    fun fetch(connectionFactory: (URL) -> HttpURLConnection = { it.openConnection() as HttpURLConnection }): ThreatIntelSnapshotV1 {
        val url = URL(CISA_KEV_URL)
        require(url.protocol == "https" && url.host == "www.cisa.gov" && url.path.endsWith("known_exploited_vulnerabilities.json"))
        val connection = connectionFactory(url)
        try {
            connection.connectTimeout = connectTimeoutMs
            connection.readTimeout = readTimeoutMs
            connection.instanceFollowRedirects = false
            connection.requestMethod = "GET"
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("User-Agent", "SiteGuard-Android/0.14.0 threat-intel-feed")
            val code = connection.responseCode
            require(code == 200) { "CISA feed HTTP status $code" }
            val length = connection.getHeaderFieldLong("Content-Length", -1L)
            require(length < 0 || length <= maxBytes) { "CISA feed Content-Length exceeds limit" }
            val bytes = connection.inputStream.use { input ->
                val out = java.io.ByteArrayOutputStream()
                val buffer = ByteArray(16 * 1024); var total = 0
                while (true) {
                    val n = input.read(buffer); if (n < 0) break
                    total += n; require(total <= maxBytes) { "CISA feed exceeds size limit" }
                    out.write(buffer, 0, n)
                }
                out.toByteArray()
            }
            val text = bytes.toString(Charsets.UTF_8)
            require(text.trimStart().startsWith("{")) { "CISA feed is not a JSON object" }
            return CisaKevFeedParserV1.parse(text)
        } finally { connection.disconnect() }
    }

    fun updateCache(cacheFile: File): ThreatIntelSnapshotV1 {
        val snapshot = fetch()
        val json = buildString {
            append("{\"catalogVersion\":").append(snapshot.catalogVersion.jsonQuote())
                .append(",\"dateReleased\":").append(snapshot.dateReleased.jsonQuote())
                .append(",\"count\":").append(snapshot.count)
                .append(",\"fetchedAtEpochMs\":").append(snapshot.fetchedAtEpochMs)
                .append(",\"sha256\":").append(snapshot.sha256.jsonQuote())
                .append(",\"source\":").append(CISA_KEV_URL.jsonQuote())
                .append(",\"entries\":[")
            append(snapshot.entries.joinToString(",") { e ->
                "{\"cveId\":${e.cveId.jsonQuote()},\"vendor\":${e.vendor.jsonQuote()},\"product\":${e.product.jsonQuote()},\"name\":${e.name.jsonQuote()},\"dateAdded\":${e.dateAdded.jsonQuote()},\"description\":${e.description.jsonQuote()},\"requiredAction\":${e.requiredAction.jsonQuote()},\"dueDate\":${e.dueDate.jsonQuote()},\"ransomwareKnown\":${e.ransomwareKnown},\"notes\":${e.notes.jsonQuote()}}"
            })
            append("]}")
        }
        cacheFile.parentFile?.mkdirs()
        val temp = File(cacheFile.parentFile ?: File("."), cacheFile.name + ".tmp")
        temp.writeText(json, Charsets.UTF_8)
        try {
            java.nio.file.Files.move(temp.toPath(), cacheFile.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING, java.nio.file.StandardCopyOption.ATOMIC_MOVE)
        } catch (ignored: Exception) {
            java.nio.file.Files.move(temp.toPath(), cacheFile.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING)
        }
        return snapshot
    }
}

private fun String.jsonQuote(): String = buildString {
    append('"')
    this@jsonQuote.forEach { c -> when (c) {
        '"' -> append("\\\""); '\\' -> append("\\\\"); '\n' -> append("\\n"); '\r' -> append("\\r"); '\t' -> append("\\t")
        else -> if (c.code < 0x20) append("\\u%04x".format(c.code)) else append(c)
    } }
    append('"')
}
