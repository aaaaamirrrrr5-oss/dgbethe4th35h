package com.siteguard.app.core

import java.io.File
import java.io.FileOutputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64

/** Append-only local JSON-free ledger. Each record is hash-linked and fsynced before return. */
class PersistentChainOfCustodyLedgerV1(private val file: File, private val maxBytes: Long = 10L * 1024 * 1024) {
    init { require(maxBytes in 4_096L..100L * 1024 * 1024) }

    @Synchronized
    fun append(evidenceId: String, action: String, actor: String, atEpochMs: Long, notes: String = ""): ChainOfCustodyEventV1 {
        require(evidenceId.isNotBlank() && action.isNotBlank() && actor.isNotBlank() && atEpochMs > 0)
        val current = readAndVerify()
        require(current.second) { "زنجیره شواهد نامعتبر است؛ append متوقف شد و فایل تغییر داده نمی‌شود." }
        val previous = current.first.lastOrNull()?.eventHash ?: "GENESIS"
        val sequence = current.first.size.toLong() + 1L
        val safeNotes = EvidenceSanitizer.sanitize(notes).take(1_000)
        val eventHash = hash(canonical(sequence, evidenceId, action, actor, atEpochMs, safeNotes, previous))
        val event = ChainOfCustodyEventV1(sequence, evidenceId, action, actor, atEpochMs, safeNotes, previous, eventHash)
        val line = encode(event) + "\n"
        val bytes = line.toByteArray(StandardCharsets.UTF_8)
        file.parentFile?.mkdirs()
        require((if (file.exists()) file.length() else 0L) + bytes.size <= maxBytes) { "سقف اندازه ledger محلی تکمیل شده است." }
        FileOutputStream(file, true).use { output -> output.write(bytes); output.fd.sync() }
        return event
    }

    @Synchronized fun snapshot(): List<ChainOfCustodyEventV1> = readAndVerify().first
    @Synchronized fun verify(): Boolean = readAndVerify().second

    @Synchronized
    fun exportText(): String {
        val (events, valid) = readAndVerify()
        require(valid) { "زنجیره شواهد معتبر نیست؛ export قابل اتکا ارائه نمی‌شود." }
        return buildString {
            append("SITEGUARD CHAIN OF CUSTODY v1\n")
            append("verified=true\nrecords=").append(events.size).append("\n")
            events.forEach { event ->
                append(event.sequence).append('|').append(event.evidenceId).append('|').append(event.action)
                    .append('|').append(event.actor).append('|').append(event.atEpochMs).append('|')
                    .append(event.previousEventHash).append('|').append(event.eventHash).append('\n')
            }
        }
    }

    private fun readAndVerify(): Pair<List<ChainOfCustodyEventV1>, Boolean> {
        if (!file.exists()) return emptyList<ChainOfCustodyEventV1>() to true
        if (file.length() > maxBytes) return emptyList<ChainOfCustodyEventV1>() to false
        val events = mutableListOf<ChainOfCustodyEventV1>()
        var previous = "GENESIS"
        return try {
            file.bufferedReader(StandardCharsets.UTF_8).useLines { lines ->
                lines.forEach { line ->
                    if (line.isBlank() || line.length > 16_384) throw IllegalArgumentException("invalid line")
                    val event = decode(line)
                    if (event.sequence != events.size + 1L || event.previousEventHash != previous) throw IllegalArgumentException("broken chain")
                    val expected = hash(canonical(event.sequence, event.evidenceId, event.action, event.actor, event.atEpochMs, event.notes, previous))
                    if (!constantTimeEquals(expected, event.eventHash)) throw IllegalArgumentException("hash mismatch")
                    events += event
                    previous = event.eventHash
                }
            }
            events.toList() to true
        } catch (ignored: Exception) {
            events.toList() to false
        }
    }

    private fun encode(event: ChainOfCustodyEventV1): String = listOf(
        event.sequence.toString(), b64(event.evidenceId), b64(event.action), b64(event.actor), event.atEpochMs.toString(),
        b64(event.notes), event.previousEventHash, event.eventHash
    ).joinToString("\t")

    private fun decode(line: String): ChainOfCustodyEventV1 {
        val p = line.split('\t')
        require(p.size == 8)
        return ChainOfCustodyEventV1(p[0].toLong(), unb64(p[1]), unb64(p[2]), unb64(p[3]), p[4].toLong(), unb64(p[5]), p[6], p[7])
    }

    private fun b64(value: String): String = Base64.getUrlEncoder().withoutPadding().encodeToString(value.toByteArray(StandardCharsets.UTF_8))
    private fun unb64(value: String): String = String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8)
    private fun canonical(sequence: Long, evidence: String, action: String, actor: String, time: Long, notes: String, previous: String) =
        listOf(sequence.toString(), b64(evidence), b64(action), b64(actor), time.toString(), b64(notes), previous).joinToString("\n")
    private fun hash(value: String): String = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(StandardCharsets.UTF_8)).joinToString("") { "%02x".format(it) }
    private fun constantTimeEquals(a: String, b: String): Boolean = MessageDigest.isEqual(a.toByteArray(StandardCharsets.US_ASCII), b.toByteArray(StandardCharsets.US_ASCII))
}
