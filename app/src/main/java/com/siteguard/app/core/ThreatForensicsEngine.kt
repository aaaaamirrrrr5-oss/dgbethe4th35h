package com.siteguard.app.core

import java.security.MessageDigest
import java.time.Instant
import java.time.OffsetDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale


enum class ThreatIndicatorType { SHA256, DOMAIN, IPV4, CVE, URI }
enum class IndicatorAssessment { CONFIRMED_BY_SOURCE, REPORTED, UNVERIFIED }

data class ThreatIntelligenceRecordV1(
    val indicatorId: String,
    val type: ThreatIndicatorType,
    val value: String,
    val publisher: String,
    val sourceUrl: String,
    val publishedAtEpochMs: Long?,
    val retrievedAtEpochMs: Long,
    val confidence: Double,
    val assessment: IndicatorAssessment,
    val expiresAtEpochMs: Long?,
    val sourceContentSha256: String,
    val notes: String = ""
)

data class ForensicEvidenceV1(
    val evidenceId: String,
    val logicalName: String,
    val mediaType: String,
    val sizeBytes: Long,
    val sha256: String,
    val capturedAtEpochMs: Long,
    val originalTimeZone: String,
    val sourceDescription: String,
    val readOnlyAcquisition: Boolean,
    val originalModified: Boolean = false
)

data class ChainOfCustodyEventV1(
    val sequence: Long,
    val evidenceId: String,
    val action: String,
    val actor: String,
    val atEpochMs: Long,
    val notes: String,
    val previousEventHash: String,
    val eventHash: String
)

data class TimelineEventV1(
    val eventId: String,
    val sourceEvidenceId: String,
    val originalTimestamp: String,
    val originalTimeZone: String,
    val normalizedUtc: String,
    val description: String,
    val classification: String = "Observation"
)

data class IndicatorMatchV1(
    val indicatorId: String,
    val evidenceId: String,
    val matchLocation: String,
    val confidence: Double,
    val interpretation: String = "تطبیق شاخص به‌تنهایی اثبات compromise نیست."
)

data class ForensicReviewV1(
    val evidence: List<ForensicEvidenceV1>,
    val custody: List<ChainOfCustodyEventV1>,
    val timeline: List<TimelineEventV1>,
    val indicatorMatches: List<IndicatorMatchV1>,
    val limitations: List<String>
)

class ChainOfCustodyLedgerV1 {
    private val events = mutableListOf<ChainOfCustodyEventV1>()

    @Synchronized
    fun append(evidenceId: String, action: String, actor: String, atEpochMs: Long, notes: String = ""): ChainOfCustodyEventV1 {
        require(evidenceId.isNotBlank() && action.isNotBlank() && actor.isNotBlank())
        require(atEpochMs > 0)
        val previous = events.lastOrNull()?.eventHash ?: "GENESIS"
        val sequence = events.size.toLong() + 1
        val canonical = listOf(sequence, evidenceId, action, actor, atEpochMs, notes, previous).joinToString("|")
        val record = ChainOfCustodyEventV1(sequence, evidenceId, action, actor, atEpochMs, notes, previous, sha256(canonical))
        events += record
        return record
    }

    @Synchronized fun snapshot(): List<ChainOfCustodyEventV1> = events.toList()

    @Synchronized
    fun verify(): Boolean {
        var previous = "GENESIS"
        events.forEachIndexed { index, event ->
            if (event.sequence != index + 1L || event.previousEventHash != previous) return false
            val canonical = listOf(event.sequence, event.evidenceId, event.action, event.actor, event.atEpochMs, event.notes, event.previousEventHash).joinToString("|")
            if (sha256(canonical) != event.eventHash) return false
            previous = event.eventHash
        }
        return true
    }

    companion object {
        private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
            .digest(value.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}

object ThreatForensicsEngineV1 {
    fun createEvidence(
        logicalName: String,
        mediaType: String,
        bytes: ByteArray,
        capturedAtEpochMs: Long,
        timeZone: String,
        sourceDescription: String,
        readOnlyAcquisition: Boolean
    ): ForensicEvidenceV1 {
        require(logicalName.isNotBlank() && capturedAtEpochMs > 0)
        require(runCatching { ZoneId.of(timeZone) }.isSuccess) { "شناسه timezone معتبر نیست." }
        return ForensicEvidenceV1(
            evidenceId = "EVD-${sha256(bytes).take(20)}", logicalName = logicalName,
            mediaType = mediaType, sizeBytes = bytes.size.toLong(), sha256 = sha256(bytes),
            capturedAtEpochMs = capturedAtEpochMs, originalTimeZone = timeZone,
            sourceDescription = sourceDescription, readOnlyAcquisition = readOnlyAcquisition,
            originalModified = false
        )
    }

    fun normalizeTimestamp(raw: String, sourceTimeZone: String): String? = runCatching {
        val instant = runCatching { Instant.parse(raw) }.getOrElse {
            val zone = ZoneId.of(sourceTimeZone)
            runCatching { OffsetDateTime.parse(raw).toInstant() }.getOrElse {
                java.time.LocalDateTime.parse(raw).atZone(zone).toInstant()
            }
        }
        DateTimeFormatter.ISO_INSTANT.format(instant)
    }.getOrNull()

    fun buildTimeline(
        events: List<Triple<String, String, String>>,
        sourceEvidenceId: String,
        sourceTimeZone: String
    ): List<TimelineEventV1> = events.mapNotNull { (rawTimestamp, description, classification) ->
        val normalized = normalizeTimestamp(rawTimestamp, sourceTimeZone) ?: return@mapNotNull null
        TimelineEventV1(
            eventId = "TL-${sha256("$sourceEvidenceId|$rawTimestamp|$description").take(16)}",
            sourceEvidenceId = sourceEvidenceId, originalTimestamp = rawTimestamp,
            originalTimeZone = sourceTimeZone, normalizedUtc = normalized,
            description = description, classification = classification
        )
    }.sortedBy { it.normalizedUtc }

    /** Exact indicator matching for supported text artifacts only. It does not execute or unpack suspicious files. */
    fun matchIndicators(
        records: List<ThreatIntelligenceRecordV1>,
        artifacts: Map<String, String>,
        nowEpochMs: Long = System.currentTimeMillis()
    ): List<IndicatorMatchV1> {
        val matches = mutableListOf<IndicatorMatchV1>()
        records.filter { record ->
            record.publisher.isNotBlank() && record.value.isNotBlank() && record.sourceUrl.startsWith("https://") &&
                record.confidence in 0.0..1.0 && record.retrievedAtEpochMs > 0 &&
                (record.expiresAtEpochMs == null || nowEpochMs <= record.expiresAtEpochMs)
        }.forEach { record ->
            artifacts.forEach { (evidenceId, content) ->
                val needle = when (record.type) {
                    ThreatIndicatorType.DOMAIN -> Regex("(?i)(?<![a-z0-9.-])${Regex.escape(record.value.lowercase(Locale.ROOT))}(?![a-z0-9.-])")
                    ThreatIndicatorType.IPV4, ThreatIndicatorType.SHA256, ThreatIndicatorType.CVE, ThreatIndicatorType.URI -> Regex(Regex.escape(record.value), RegexOption.IGNORE_CASE)
                }
                val match = needle.find(content)
                if (match != null) matches += IndicatorMatchV1(
                    record.indicatorId, evidenceId, "character-offset:${match.range.first}",
                    record.confidence.coerceIn(0.0, 1.0),
                    if (record.assessment == IndicatorAssessment.REPORTED) "شاخص فقط گزارش شده است؛ تطبیق متنی اثبات compromise نیست."
                    else "شاخص در داده بررسی‌شده پیدا شد؛ تطبیق به‌تنهایی اثبات compromise نیست."
                )
            }
        }
        return matches
    }

    fun review(evidence: List<ForensicEvidenceV1>, custody: List<ChainOfCustodyEventV1>, timeline: List<TimelineEventV1>, matches: List<IndicatorMatchV1>, custodyValid: Boolean): ForensicReviewV1 =
        ForensicReviewV1(evidence.toList(), custody.toList(), timeline.toList(), matches.toList(), buildList {
            if (!custodyValid) add("زنجیره تحویل تغییر کرده یا قابل اعتبارسنجی نیست.")
            if (evidence.any { it.originalModified }) add("حداقل یک evidence با وضعیت originalModified ثبت شده؛ اصل شواهد باید بررسی شود.")
            add("شاخص threat intelligence نشانه بررسی است، نه اثبات آلودگی یا compromise.")
            add("فایل مشکوک در این ماژول اجرا نمی‌شود؛ تحلیل بدافزار باید در آزمایشگاه ایزوله مستقل انجام شود.")
            add("فقط قالب‌های زمانی و artifactهای متنی پشتیبانی‌شده تحلیل می‌شوند.")
        })

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it) }
    private fun sha256(value: String): String = sha256(value.toByteArray(Charsets.UTF_8))
}
