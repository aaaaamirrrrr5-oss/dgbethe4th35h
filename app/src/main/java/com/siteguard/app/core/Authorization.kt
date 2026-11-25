package com.siteguard.app.core

import java.net.IDN
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.URL
import java.util.Locale
import java.util.UUID

/** A short-lived, host- and port-bound record created only after the user confirms authorization. */
data class AuthorizationManifest(
    val schemaVersion: Int = 1,
    val authorizationId: String = UUID.randomUUID().toString(),
    val ownerDeclaration: String = "User declares ownership or written authorization",
    val authorizedHosts: Set<String>,
    val allowedPorts: Set<Int>,
    val allowedPathPrefixes: Set<String> = setOf("/"),
    val excludedPaths: Set<String> = emptySet(),
    val allowedMethods: Set<String> = setOf("PASSIVE_HTTP_GET"),
    val excludedHosts: Set<String> = emptySet(),
    val allowPrivateNetwork: Boolean = false,
    val validFromEpochMs: Long = System.currentTimeMillis(),
    val validUntilEpochMs: Long = System.currentTimeMillis() + 60 * 60 * 1000L,
    val maxRequests: Int = 1,
    val requestsPerMinute: Int = 1,
    val emergencyStopDescription: String = "Cancel the running assessment from the app"
) {
    companion object {
        fun forSingleTarget(rawUrl: String, allowPrivateNetwork: Boolean): AuthorizationManifest? {
            val normalized = normalizeUrl(rawUrl) ?: return null
            val parsed = runCatching { URL(normalized) }.getOrNull() ?: return null
            val host = canonicalHost(parsed.host) ?: return null
            val port = if (parsed.port >= 0) parsed.port else if (parsed.protocol.equals("https", true)) 443 else 80
            return AuthorizationManifest(
                authorizedHosts = setOf(host),
                allowedPorts = setOf(port),
                allowedPathPrefixes = setOf(parsed.path.ifBlank { "/" }),
                allowPrivateNetwork = allowPrivateNetwork
            )
        }
    }
}

data class ScopeDecision(
    val allowed: Boolean,
    val normalizedUrl: String = "",
    val reason: String = "",
    val authorizationId: String = ""
)

/** Strict path validation shared by URL inputs and the caller-provided scope manifest. */
private object AuthorizationPathPolicy {
    private val malformedPercent = Regex("%(?![0-9a-fA-F]{2})")
    // Reject encoded traversal/separators, controls and a second decoding layer (%25).
    private val ambiguousEncoding = Regex("(?i)%(?:2e|2f|5c|00|0a|0d|25)")

    fun canonical(path: String): String? {
        if (path.isEmpty() || path.length > 2_048 || !path.startsWith('/')) return null
        if (path.any { it.code < 0x20 || it.code == 0x7f || it == '\\' || it == '?' || it == '#' }) return null
        if (malformedPercent.containsMatchIn(path) || ambiguousEncoding.containsMatchIn(path)) return null
        if (path.split('/').any { it == "." || it == ".." }) return null
        return path
    }

    fun matches(path: String, prefix: String): Boolean {
        val base = prefix.trimEnd('/').ifEmpty { "/" }
        return base == "/" || path == base || path.startsWith("$base/")
    }
}

object ScopeEnforcer {
    fun validate(rawUrl: String, manifest: AuthorizationManifest?, now: Long = System.currentTimeMillis()): ScopeDecision {
        if (manifest == null) return ScopeDecision(false, reason = "مجوز مستند و محدود به هدف ایجاد نشده است.")
        if (manifest.schemaVersion != 1) return ScopeDecision(false, reason = "نسخه مانیفست مجوز پشتیبانی نمی‌شود.")
        if (manifest.authorizationId.isBlank() || manifest.authorizationId.length > 128 ||
            manifest.authorizationId.any { it.code < 0x20 || it.code == 0x7f } ||
            manifest.ownerDeclaration.isBlank() || manifest.ownerDeclaration.length > 1_000 ||
            manifest.ownerDeclaration.any { it.code < 0x20 && it != '\n' && it != '\t' }) {
            return ScopeDecision(false, reason = "شناسه مجوز یا اظهار مالکیت خالی، بیش‌ازحد بزرگ یا نامعتبر است.")
        }
        if (manifest.validFromEpochMs <= 0 || manifest.validUntilEpochMs < manifest.validFromEpochMs ||
            now !in manifest.validFromEpochMs..manifest.validUntilEpochMs) {
            return ScopeDecision(false, reason = "بازه زمانی مجوز بررسی نامعتبر، پایان‌یافته یا هنوز آغازنشده است.")
        }
        if (manifest.maxRequests !in 1..100_000 || manifest.requestsPerMinute !in 1..10_000) {
            return ScopeDecision(false, reason = "بودجه درخواست مجاز نامعتبر است.")
        }
        if (manifest.allowedPorts.isEmpty() || manifest.allowedPorts.size > 100 || manifest.allowedPorts.any { it !in 1..65_535 }) {
            return ScopeDecision(false, reason = "فهرست درگاه‌های مجاز نامعتبر است.")
        }
        if (manifest.allowedMethods != setOf("PASSIVE_HTTP_GET")) {
            return ScopeDecision(false, reason = "فقط روش غیرفعال HTTP GET در این ابزار پشتیبانی و مجاز است.")
        }
        if (manifest.authorizedHosts.isEmpty() || manifest.authorizedHosts.size > 100 || manifest.excludedHosts.size > 100 ||
            manifest.allowedPathPrefixes.isEmpty() || manifest.allowedPathPrefixes.size > 100 || manifest.excludedPaths.size > 100) {
            return ScopeDecision(false, reason = "فهرست میزبان‌ها یا مسیرهای مجاز از محدوده امن خارج است.")
        }

        val normalized = normalizeUrl(rawUrl)
            ?: return ScopeDecision(false, reason = "آدرس نامعتبر است؛ فقط HTTP و HTTPS با مسیر امن پشتیبانی می‌شوند.")
        val parsed = runCatching { URL(normalized) }.getOrNull()
            ?: return ScopeDecision(false, reason = "آدرس قابل تجزیه نیست.")
        val host = canonicalHost(parsed.host)
            ?: return ScopeDecision(false, reason = "نام میزبان معتبر نیست.")
        val port = if (parsed.port >= 0) parsed.port else if (parsed.protocol.equals("https", true)) 443 else 80
        val path = AuthorizationPathPolicy.canonical(parsed.path.ifBlank { "/" })
            ?: return ScopeDecision(false, reason = "مسیر مقصد دارای شکل مبهم، control character یا traversal است.")

        val authorized = manifest.authorizedHosts.mapNotNull(::canonicalHost)
        val excluded = manifest.excludedHosts.mapNotNull(::canonicalHost)
        if (authorized.size != manifest.authorizedHosts.size || excluded.size != manifest.excludedHosts.size) {
            return ScopeDecision(false, reason = "یکی از میزبان‌های مانیفست معتبر نیست.")
        }
        if (host in excluded || host !in authorized.toSet()) {
            return ScopeDecision(false, reason = "میزبان خارج از محدوده دقیق مجوز است.")
        }
        if (port !in manifest.allowedPorts) return ScopeDecision(false, reason = "درگاه هدف در مانیفست مجاز نشده است.")

        val allowedPaths = manifest.allowedPathPrefixes.mapNotNull(AuthorizationPathPolicy::canonical)
        val excludedPaths = manifest.excludedPaths.mapNotNull(AuthorizationPathPolicy::canonical)
        if (allowedPaths.size != manifest.allowedPathPrefixes.size || excludedPaths.size != manifest.excludedPaths.size) {
            return ScopeDecision(false, reason = "یکی از مسیرهای مجاز یا ممنوع مانیفست دارای شکل نامعتبر است.")
        }
        val inAllowedPath = allowedPaths.any { AuthorizationPathPolicy.matches(path, it) }
        val inExcludedPath = excludedPaths.any { AuthorizationPathPolicy.matches(path, it) }
        if (!inAllowedPath || inExcludedPath) {
            return ScopeDecision(false, reason = "مسیر خارج از محدوده مجاز مانیفست است.")
        }
        return ScopeDecision(true, normalized, "هدف با میزبان، درگاه و مسیر مجاز تطبیق دارد.", manifest.authorizationId)
    }
}

fun normalizeUrl(raw: String): String? {
    val value = raw.trim()
    if (value.isBlank() || value.length > 4_096 ||
        value.any { it.isWhitespace() || it.code < 0x20 || it.code == 0x7f || it == '\\' }) return null
    val candidate = if (value.startsWith("http://", true) || value.startsWith("https://", true)) value else "https://$value"
    return runCatching {
        val parsed = URL(candidate)
        val scheme = parsed.protocol.lowercase(Locale.ROOT)
        val path = parsed.path.ifBlank { "/" }
        val host = canonicalHost(parsed.host)
        if (scheme !in setOf("http", "https") || host == null || parsed.userInfo != null || parsed.ref != null ||
            parsed.port !in -1..65_535 || parsed.port == 0 || parsed.host.contains('%') ||
            AuthorizationPathPolicy.canonical(path) == null || parsed.query.orEmpty().length > 2_048 ||
            parsed.query.orEmpty().any { it.code < 0x20 || it.code == 0x7f }) null
        else parsed.toExternalForm()
    }.getOrNull()
}

/** Canonicalizes DNS names and numeric IP literals without performing a hostname lookup. */
fun canonicalHost(rawHost: String): String? = runCatching {
    val host = rawHost.trim().removeSurrounding("[", "]").trimEnd('.').lowercase(Locale.ROOT)
    if (host.isBlank() || host.length > 253 || host.contains('%')) return null
    if (host.contains(':')) {
        // A colon forces a numeric IPv6 parse; scoped/zone identifiers are rejected above.
        val address = InetAddress.getByName(host)
        if (address !is Inet6Address) return null
        return address.hostAddress.substringBefore('%').lowercase(Locale.ROOT)
    }
    if (host.all { it.isDigit() || it == '.' }) {
        val parts = host.split('.')
        if (parts.size != 4 || parts.any { it.isEmpty() || it.length > 3 || (it.length > 1 && it.startsWith('0')) }) return null
        if (parts.any { it.toIntOrNull() !in 0..255 }) return null
        return parts.joinToString(".") { it.toInt().toString() }
    }
    val ascii = IDN.toASCII(host, IDN.USE_STD3_ASCII_RULES).lowercase(Locale.ROOT)
    if (ascii.length > 253 || ascii.split('.').any { it.isEmpty() || it.length > 63 }) return null
    ascii
}.getOrNull()

/** Conservatively classifies local, private, shared, documentation and reserved IP ranges. */
object AddressPolicy {
    /** True when the address is not an ordinary globally routable unicast address (private, reserved, special-use, transition). */
    fun isNonPublic(address: InetAddress): Boolean {
        if (address.isAnyLocalAddress || address.isLoopbackAddress || address.isLinkLocalAddress ||
            address.isSiteLocalAddress || address.isMulticastAddress) return true
        val bytes = address.address
        return when (address) {
            is Inet4Address -> isNonPublicV4(bytes)
            is Inet6Address -> isNonPublicV6(bytes)
            else -> true
        }
    }

    /** Exact IANA IPv4 special-use blocks (RFC 6890 and updates); 192.0.0.0/16 and 198.51.0.0/16 are no longer over-blocked. */
    internal fun isNonPublicV4(bytes: ByteArray): Boolean {
        if (bytes.size != 4) return true
        val a = bytes[0].toInt() and 0xff
        val b = bytes[1].toInt() and 0xff
        val c = bytes[2].toInt() and 0xff
        return a == 0 || a == 10 || a == 127 || a >= 224 ||
            (a == 100 && b in 64..127) || (a == 169 && b == 254) ||
            (a == 172 && b in 16..31) || (a == 192 && b == 0 && c == 0) ||
            (a == 192 && b == 0 && c == 2) || (a == 192 && b == 88 && c == 99) ||
            (a == 192 && b == 168) || (a == 198 && (b == 18 || b == 19)) ||
            (a == 198 && b == 51 && c == 100) || (a == 203 && b == 0 && c == 113)
    }

    /** IPv6 special-use and transition ranges are blocked or judged by embedded IPv4 address. */
    internal fun isNonPublicV6(bytes: ByteArray): Boolean {
        if (bytes.size != 16) return true
        fun u(i: Int) = bytes[i].toInt() and 0xff
        val first = u(0)
        val second = u(1)
        if ((first and 0xfe) == 0xfc) return true
        if (first == 0xfe && (second and 0xc0) == 0x80) return true
        if (first == 0xfe && (second and 0xc0) == 0xc0) return true
        if (first == 0x00) {
            if (second == 0x64 && u(2) == 0xff && u(3) == 0x9b && (4..11).all { u(it) == 0 }) {
                return isNonPublicV4(bytes.copyOfRange(12, 16))
            }
            return true
        }
        if (first == 0x01 && second == 0x00 && (2..7).all { u(it) == 0 }) return true
        if (first == 0x20 && second == 0x01 && u(2) <= 0x01) return true
        if (first == 0x20 && second == 0x01 && u(2) == 0x0d && u(3) == 0xb8) return true
        if (first == 0x3f && second == 0xff && (u(2) and 0xf0) == 0x00) return true
        if (first == 0x5f && second == 0x00) return true
        if (first == 0x20 && second == 0x02) return isNonPublicV4(bytes.copyOfRange(2, 6))
        if (first == 0xff) return true
        return false
    }
}

/**
 * Request budget for a short-lived authorization manifest. Counters live in memory and, once a [Store] is attached
 * (MainActivity / the WorkManager worker do this), are persisted so a process restart can no longer reset the budget.
 */
object AuthorizationBudget {
    private data class Usage(
        val timestamps: java.util.ArrayDeque<Long> = java.util.ArrayDeque(),
        var total: Int = 0,
        val validUntilEpochMs: Long
    )
    private val usage = java.util.concurrent.ConcurrentHashMap<String, Usage>()

    /** Minimal persistence port (the budget holds only ids, counters and timestamps, never targets or secrets). */
    interface Store { fun load(): String?; fun save(json: String) }
    @Volatile private var store: Store? = null

    /** Attaches the store once per process (or again with [force]) and merges its persisted counters (max wins). */
    @Synchronized
    fun attachStore(newStore: Store, now: Long = System.currentTimeMillis(), force: Boolean = false) {
        if (store != null && !force) return
        store = newStore
        // Plain tab-separated text (id URL-encoded, until, total, timestamps) so this file keeps compiling with plain kotlinc
        // in tools/run-advanced-smoke-tests.sh, where the Android JSON classes are not on the classpath.
        runCatching {
            val raw = newStore.load() ?: return@runCatching
            for (line in raw.lineSequence()) {
                val parts = line.split('\t')
                if (parts.size < 3) continue
                val id = java.net.URLDecoder.decode(parts[0], "UTF-8")
                val until = parts[1].toLongOrNull() ?: continue
                val total = parts[2].toIntOrNull() ?: continue
                if (id.isBlank() || until < now) continue
                val bucket = usage.computeIfAbsent(id) { Usage(validUntilEpochMs = until) }
                synchronized(bucket) {
                    bucket.total = maxOf(bucket.total, total)
                    if (bucket.timestamps.isEmpty() && parts.size > 3 && parts[3].isNotEmpty()) {
                        parts[3].split(',').mapNotNull { it.toLongOrNull() }
                            .filter { now - it in 0 until 60_000L }
                            .forEach { bucket.timestamps.addLast(it) }
                    }
                }
            }
        }
    }

    internal fun detachStore() { store = null }
    internal fun resetInMemoryForTests() { usage.clear() }

    fun consume(manifest: AuthorizationManifest, now: Long = System.currentTimeMillis()): Boolean {
        discardExpired(now)
        if (manifest.authorizationId.isBlank() || manifest.maxRequests !in 1..100_000 ||
            manifest.requestsPerMinute !in 1..10_000 || now !in manifest.validFromEpochMs..manifest.validUntilEpochMs) return false
        val bucket = usage.computeIfAbsent(manifest.authorizationId) { Usage(validUntilEpochMs = manifest.validUntilEpochMs) }
        val allowed = synchronized(bucket) {
            while (bucket.timestamps.isNotEmpty() && now - bucket.timestamps.peekFirst() >= 60_000L) bucket.timestamps.removeFirst()
            if (bucket.total >= manifest.maxRequests || bucket.timestamps.size >= manifest.requestsPerMinute) {
                false
            } else {
                bucket.timestamps.addLast(now)
                bucket.total++
                true
            }
        }
        if (allowed) persist()
        return allowed
    }

    private fun persist() {
        val target = store ?: return
        runCatching {
            val text = buildString {
                for ((id, bucket) in usage) {
                    synchronized(bucket) {
                        append(java.net.URLEncoder.encode(id, "UTF-8")).append('\t')
                            .append(bucket.validUntilEpochMs).append('\t')
                            .append(bucket.total).append('\t')
                            .append(bucket.timestamps.joinToString(",")).append('\n')
                    }
                }
            }
            target.save(text)
        }
    }

    /** Removes entries only after their authorization expiry, keeping the short-lived registry bounded. */
    fun discardExpired(now: Long = System.currentTimeMillis()) {
        usage.entries.removeIf { (_, bucket) -> bucket.validUntilEpochMs < now }
    }
}
