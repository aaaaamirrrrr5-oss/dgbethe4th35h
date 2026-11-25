package com.siteguard.app.core

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import org.json.JSONObject
import java.security.MessageDigest

/** Persistent, offline SQLite/FTS4 store for bundled, source-attributed knowledge records. */
data class LocalKnowledgeSearchHit(
    val recordId: String,
    val cwe: String,
    val title: String,
    val body: String,
    val sourcePublisher: String,
    val sourceUrl: String,
    val confidence: String,
    val reviewStatus: String
)

data class LocalKnowledgeStoreStatus(
    val schemaVersion: Int,
    val recordCount: Int,
    val sourceCount: Int,
    val mode: String,
    val fts4Enabled: Boolean,
    val isLiveFeed: Boolean,
    val lastFetchedEpochMs: Long?,
    val note: String
)

class LocalSecurityKnowledgeStore(context: Context) : SQLiteOpenHelper(
    context.applicationContext,
    DATABASE_NAME,
    null,
    DATABASE_VERSION
) {
    fun initialize() {
        writableDatabase
    }

    override fun onConfigure(db: SQLiteDatabase) {
        super.onConfigure(db)
        db.setForeignKeyConstraintsEnabled(true)
    }

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """CREATE TABLE IF NOT EXISTS knowledge_sources (
                source_id TEXT PRIMARY KEY NOT NULL,
                publisher TEXT NOT NULL,
                url TEXT NOT NULL,
                topic TEXT NOT NULL,
                retrieval_mode TEXT NOT NULL,
                retrieved_at_epoch_ms INTEGER,
                content_sha256 TEXT NOT NULL,
                license_status TEXT NOT NULL,
                parser_version TEXT NOT NULL,
                confidence TEXT NOT NULL,
                review_status TEXT NOT NULL
            )""".trimIndent()
        )
        db.execSQL(
            """CREATE TABLE IF NOT EXISTS knowledge_records (
                record_id TEXT PRIMARY KEY NOT NULL,
                record_type TEXT NOT NULL,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                cwe TEXT,
                source_id TEXT NOT NULL,
                source_url TEXT NOT NULL,
                published_at TEXT,
                retrieved_at_epoch_ms INTEGER,
                content_sha256 TEXT NOT NULL,
                parser_version TEXT NOT NULL,
                confidence TEXT NOT NULL,
                review_status TEXT NOT NULL,
                FOREIGN KEY(source_id) REFERENCES knowledge_sources(source_id)
            )""".trimIndent()
        )
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_knowledge_records_cwe ON knowledge_records(cwe)")
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_knowledge_records_source ON knowledge_records(source_id)")
        val ftsCreated = runCatching {
            db.execSQL("CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_fts USING fts4(record_id, title, body, tokenize=unicode61)")
        }.isSuccess
        if (!ftsCreated) {
            // Graceful fallback for SQLite builds without FTS4; search remains local and parameterized.
            db.execSQL("CREATE TABLE IF NOT EXISTS knowledge_fts (record_id TEXT PRIMARY KEY NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL)")
            db.execSQL("CREATE INDEX IF NOT EXISTS idx_knowledge_search_title ON knowledge_fts(title)")
        }
        seedBundledSnapshot(db)
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        // Never drop local knowledge on upgrade. Add explicit, transactional migrations here.
        if (oldVersion < 1 && newVersion >= 1) onCreate(db)
    }

    fun search(query: String, limit: Int = 20): List<LocalKnowledgeSearchHit> {
        if (query.isBlank() || limit !in 1..100) return emptyList()
        val tokens = Regex("[\\p{L}\\p{N}_-]+")
            .findAll(query.take(160))
            .map { it.value.replace("\"", "\"\"") }
            .filter { it.isNotBlank() }
            .toList()
        if (tokens.isEmpty()) return emptyList()
        val matchExpression = tokens.joinToString(" AND ") { "\"$it\"" }
        val db = readableDatabase
        val ftsEnabled = isFts4Enabled(db)
        val sql: String
        val args: Array<String>
        if (ftsEnabled) {
            sql = """SELECT r.record_id, r.cwe, r.title, r.body, s.publisher, r.source_url,
                r.confidence, r.review_status
                FROM knowledge_fts f
                JOIN knowledge_records r ON r.record_id = f.record_id
                JOIN knowledge_sources s ON s.source_id = r.source_id
                WHERE knowledge_fts MATCH ?
                ORDER BY r.record_type, r.title
                LIMIT ?""".trimIndent()
            args = arrayOf(matchExpression, limit.toString())
        } else {
            val clauses = tokens.joinToString(" AND ") { "(r.title LIKE ? ESCAPE '\\' OR r.body LIKE ? ESCAPE '\\')" }
            val likeArgs = tokens.flatMap { token ->
                val escaped = token.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                listOf("%$escaped%", "%$escaped%")
            }
            sql = """SELECT r.record_id, r.cwe, r.title, r.body, s.publisher, r.source_url,
                r.confidence, r.review_status FROM knowledge_records r
                JOIN knowledge_sources s ON s.source_id = r.source_id
                WHERE $clauses ORDER BY r.record_type, r.title LIMIT ?""".trimIndent()
            args = (likeArgs + limit.toString()).toTypedArray()
        }
        return db.rawQuery(sql, args).use { cursor ->
            buildList {
                while (cursor.moveToNext()) {
                    add(
                        LocalKnowledgeSearchHit(
                            recordId = cursor.getString(0),
                            cwe = cursor.getString(1).orEmpty(),
                            title = cursor.getString(2),
                            body = cursor.getString(3),
                            sourcePublisher = cursor.getString(4),
                            sourceUrl = cursor.getString(5),
                            confidence = cursor.getString(6),
                            reviewStatus = cursor.getString(7)
                        )
                    )
                }
            }
        }
    }

    fun lookupCwe(cwe: String): LocalKnowledgeSearchHit? {
        if (!Regex("(?i)^CWE-[0-9]{1,6}$").matches(cwe.trim())) return null
        val sql = """SELECT r.record_id, r.cwe, r.title, r.body, s.publisher, r.source_url,
            r.confidence, r.review_status
            FROM knowledge_records r JOIN knowledge_sources s ON s.source_id = r.source_id
            WHERE r.cwe = ? LIMIT 1""".trimIndent()
        return readableDatabase.rawQuery(sql, arrayOf(cwe.trim().uppercase())).use { cursor ->
            if (!cursor.moveToFirst()) null else LocalKnowledgeSearchHit(
                recordId = cursor.getString(0), cwe = cursor.getString(1).orEmpty(),
                title = cursor.getString(2), body = cursor.getString(3),
                sourcePublisher = cursor.getString(4), sourceUrl = cursor.getString(5),
                confidence = cursor.getString(6), reviewStatus = cursor.getString(7)
            )
        }
    }

    fun status(): LocalKnowledgeStoreStatus {
        val db = readableDatabase
        val records = count(db, "knowledge_records")
        val sources = count(db, "knowledge_sources")
        return LocalKnowledgeStoreStatus(
            schemaVersion = DATABASE_VERSION,
            recordCount = records,
            sourceCount = sources,
            mode = if (isFts4Enabled(db)) "offline-curated-sqlite-fts4" else "offline-curated-sqlite-like-fallback",
            fts4Enabled = isFts4Enabled(db),
            isLiveFeed = false,
            lastFetchedEpochMs = null,
            note = "این پایگاه از داده‌های مرجع محلی seed شده است؛ feed زنده یا تاریخ دریافت منبع ادعا نمی‌شود."
        )
    }

    fun statusJson(): JSONObject = status().let { value -> JSONObject().apply {
        put("schema_version", value.schemaVersion)
        put("record_count", value.recordCount)
        put("source_count", value.sourceCount)
        put("mode", value.mode)
        put("fts4_enabled", value.fts4Enabled)
        put("is_live_feed", value.isLiveFeed)
        put("last_fetched_epoch_ms", value.lastFetchedEpochMs ?: JSONObject.NULL)
        put("note", value.note)
    } }

    private fun seedBundledSnapshot(db: SQLiteDatabase) {
        if (count(db, "knowledge_records") > 0) return
        db.beginTransaction()
        try {
            LocalSecurityKnowledgePack.sources.forEach { source ->
                val values = ContentValues().apply {
                    put("source_id", source.sourceId)
                    put("publisher", source.publisher)
                    put("url", source.url)
                    put("topic", source.topic)
                    put("retrieval_mode", source.retrievalMode)
                    putNull("retrieved_at_epoch_ms")
                    put("content_sha256", sha256("${source.sourceId}|${source.publisher}|${source.url}|${source.topic}"))
                    put("license_status", "REFERENCE_ONLY_REVIEW_PUBLISHER_TERMS")
                    put("parser_version", "siteguard-knowledge-parser-1")
                    put("confidence", "SOURCE_METADATA_ONLY")
                    put("review_status", "NOT_FETCHED")
                }
                db.insertWithOnConflict("knowledge_sources", null, values, SQLiteDatabase.CONFLICT_IGNORE)
            }
            SecurityKnowledgeBase.entries.forEach { entry ->
                val sourceUrl = "https://cwe.mitre.org/data/definitions/${entry.cwe.removePrefix("CWE-")}.html"
                val body = "${entry.summary}\n\nپیشگیری: ${entry.prevention}"
                val recordId = "weakness:${entry.cwe.lowercase()}"
                val canonical = "$recordId|${entry.name}|$body|$sourceUrl"
                val values = ContentValues().apply {
                    put("record_id", recordId)
                    put("record_type", "WEAKNESS")
                    put("title", "${entry.cwe} — ${entry.name}")
                    put("body", body)
                    put("cwe", entry.cwe)
                    put("source_id", "mitre-cwe")
                    put("source_url", sourceUrl)
                    putNull("published_at")
                    putNull("retrieved_at_epoch_ms")
                    put("content_sha256", sha256(canonical))
                    put("parser_version", "siteguard-knowledge-parser-1")
                    put("confidence", "CURATED_REFERENCE_NOT_ADVISORY")
                    put("review_status", "LOCAL_CURATED_REVIEW_REQUIRED")
                }
                db.insertWithOnConflict("knowledge_records", null, values, SQLiteDatabase.CONFLICT_IGNORE)
                db.insertWithOnConflict("knowledge_fts", null, ContentValues().apply {
                    put("record_id", recordId)
                    put("title", "${entry.cwe} — ${entry.name}")
                    put("body", body)
                }, SQLiteDatabase.CONFLICT_IGNORE)
            }
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    private fun isFts4Enabled(db: SQLiteDatabase): Boolean = db.rawQuery(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='knowledge_fts' LIMIT 1", null
    ).use { cursor ->
        cursor.moveToFirst() && cursor.getString(0).orEmpty().contains("using fts4", ignoreCase = true)
    }

    private fun count(db: SQLiteDatabase, table: String): Int {
        require(table in setOf("knowledge_records", "knowledge_sources"))
        return db.rawQuery("SELECT COUNT(*) FROM $table", null).use { cursor ->
            if (cursor.moveToFirst()) cursor.getInt(0) else 0
        }
    }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }

    companion object {
        private const val DATABASE_NAME = "siteguard_knowledge.db"
        private const val DATABASE_VERSION = 1
    }
}
