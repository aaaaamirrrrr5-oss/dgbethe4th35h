package com.siteguard.app.core

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URI
import java.security.MessageDigest
import java.util.ArrayDeque
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/** Strictly bounded, passive GET discovery. It never submits forms, follows external links or sends credentials. */
data class WebsiteDiscoveryOptionsV1(
    val maxPages: Int = 8,
    val maxDepth: Int = 1,
    val maxBodyBytes: Int = 128 * 1024,
    val connectTimeoutMs: Int = 5_000,
    val readTimeoutMs: Int = 5_000,
    val honorRequestRate: Boolean = true,
    val maxDurationMs: Long = 60_000L
) {
    init {
        require(maxPages in 1..25)
        require(maxDepth in 0..2)
        require(maxBodyBytes in 8 * 1024..256 * 1024)
        require(connectTimeoutMs in 1_000..10_000 && readTimeoutMs in 1_000..10_000)
        require(maxDurationMs in 5_000L..180_000L)
    }
}

data class WebsiteDiscoveredPageV1(
    val url: String,
    val statusCode: Int,
    val contentType: String,
    val title: String,
    val depth: Int,
    val connectedIp: String,
    val bodySha256: String,
    val discoveredLinks: Int,
    val responseHeaders: Map<String, String>
)

data class WebsiteDiscoveryEventV1(val url: String, val status: String, val reason: String)
data class WebsiteDiscoveryResultV1(
    val engagementId: String,
    val startedAtEpochMs: Long,
    val completedAtEpochMs: Long,
    val pages: List<WebsiteDiscoveredPageV1>,
    val events: List<WebsiteDiscoveryEventV1>,
    val requestsUsed: Int,
    val limitations: List<String>
) {
    val stoppedByBudget: Boolean get() = events.any { it.status == "BUDGET_BLOCKED" }
}

private data class PinnedHttpResponseV1(
    val status: Int,
    val headers: Map<String, String>,
    val body: ByteArray,
    val ip: String,
    val tls: TlsSessionInfoV1? = null
)

object WebsiteDiscoveryEngineV1 {
    suspend fun discover(
        startUrl: String,
        manifest: WebsiteEngagementManifestV2,
        options: WebsiteDiscoveryOptionsV1 = WebsiteDiscoveryOptionsV1()
    ): WebsiteDiscoveryResultV1 = withTimeout(options.maxDurationMs) {
        withContext(Dispatchers.IO) {
        val started = System.currentTimeMillis()
        val pages = mutableListOf<WebsiteDiscoveredPageV1>()
        val events = mutableListOf<WebsiteDiscoveryEventV1>()
        val queue = ArrayDeque<Pair<String, Int>>()
        val visited = linkedSetOf<String>()
        var requests = 0
        val startHasQuery = runCatching { URI(startUrl).rawQuery != null }.getOrDefault(true)
        if (startHasQuery) {
            return@withContext WebsiteDiscoveryResultV1(manifest.engagementId, started, System.currentTimeMillis(), emptyList(),
                listOf(WebsiteDiscoveryEventV1(startUrl.substringBefore('?'), "BLOCKED_QUERY", "برای جلوگیری از ثبت/ارسال token و پارامترهای حساس، crawler فقط URL بدون query string را می‌پذیرد.")), 0,
                listOf("هیچ اتصال شبکه‌ای انجام نشد؛ query string در ورودی اولیه مجاز نیست."))
        }
        val initial = manifest.authorizeUrl(startUrl, WebsiteTestClassV2.PASSIVE_REVIEW, requests, started)
        if (!initial.allowed) {
            return@withContext WebsiteDiscoveryResultV1(manifest.engagementId, started, System.currentTimeMillis(), emptyList(),
                listOf(WebsiteDiscoveryEventV1(startUrl, "BLOCKED_SCOPE", initial.reason)), 0,
                listOf("هیچ اتصال شبکه‌ای انجام نشد؛ URL با مانیفست تعامل تطبیق نداشت."))
        }
        queue.add(initial.normalizedUrl to 0)
        var lastRequestAt = 0L
        while (queue.isNotEmpty() && pages.size < options.maxPages) {
            currentCoroutineContext().ensureActive()
            val (candidate, depth) = queue.removeFirst()
            if (requests >= minOf(options.maxPages, manifest.maxRequests)) {
                events += WebsiteDiscoveryEventV1(candidate, "BUDGET_BLOCKED", "بودجه درخواست یا سقف صفحه مصرف شده است.")
                break
            }
            val decision = manifest.authorizeUrl(candidate, WebsiteTestClassV2.PASSIVE_REVIEW, requests)
            if (!decision.allowed) {
                events += WebsiteDiscoveryEventV1(candidate, "BLOCKED_SCOPE", decision.reason)
                continue
            }
            val canonical = decision.normalizedUrl.substringBefore('#')
            if (!visited.add(canonical)) continue
            if (options.honorRequestRate && lastRequestAt > 0L) {
                val minimumDelay = (60_000L / manifest.requestsPerMinute.coerceAtLeast(1)).coerceAtMost(60_000L)
                val elapsed = System.currentTimeMillis() - lastRequestAt
                if (elapsed < minimumDelay) delay(minimumDelay - elapsed)
            }
            // Count every attempted request, including DNS/connect/TLS/read failures, against the budget.
            requests++
            lastRequestAt = System.currentTimeMillis()
            try {
                currentCoroutineContext().ensureActive()
                val response = fetchPinned(canonical, manifest, options)
                currentCoroutineContext().ensureActive()
                val contentType = response.headers["content-type"].orEmpty().substringBefore(';').trim().lowercase()
                val html = contentType == "text/html" || contentType == "application/xhtml+xml"
                val bodyText = if (html) response.body.toString(Charsets.UTF_8) else ""
                val links = if (html && depth < options.maxDepth) extractLinks(bodyText, canonical) else emptyList()
                val title = if (html) Regex("(?is)<title\\b[^>]*>(.*?)</title>").find(bodyText)?.groupValues?.get(1)
                    ?.replace(Regex("\\s+"), " ")?.trim()?.take(180).orEmpty() else ""
                pages += WebsiteDiscoveredPageV1(
                    url = canonical, statusCode = response.status, contentType = contentType,
                    title = EvidenceSanitizer.sanitize(title), depth = depth, connectedIp = response.ip,
                    bodySha256 = sha256(response.body), discoveredLinks = links.size,
                    responseHeaders = response.headers.filterKeys { it in SAFE_RESPONSE_HEADERS }.mapValues { EvidenceSanitizer.sanitize(it.value).take(500) }
                )
                events += WebsiteDiscoveryEventV1(canonical, "FETCHED", "HTTP ${response.status}; body=${response.body.size} bytes; linked URLs=${links.size}.")
                links.forEach { link ->
                    val child = manifest.authorizeUrl(link, WebsiteTestClassV2.PASSIVE_REVIEW, requests)
                    if (child.allowed && child.normalizedUrl !in visited) queue.add(child.normalizedUrl to depth + 1)
                    else if (!child.allowed) events += WebsiteDiscoveryEventV1(link, "LINK_NOT_FOLLOWED", child.reason)
                }
                // A redirect is recorded only. It is never followed automatically; the owner must add a separate explicit target.
                if (response.status in 300..399) {
                    val location = response.headers["location"]
                    if (!location.isNullOrBlank()) events += WebsiteDiscoveryEventV1(canonical, "REDIRECT_NOT_FOLLOWED", "پاسخ redirect به مقصد جدید دریافت شد؛ برای جلوگیری از scope escape به‌صورت خودکار دنبال نشد.")
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (e: Exception) {
                val tls = if (canonical.startsWith("https://", ignoreCase = true)) TlsFailureClassifier.classify(e) else null
                if (tls != null) {
                    events += WebsiteDiscoveryEventV1(canonical, "TLS_VALIDATION_FAILED", "${tls.kind.name}; ${tls.exceptionChain}; ${tls.detail}")
                } else {
                    events += WebsiteDiscoveryEventV1(canonical, "REQUEST_FAILED", "${e.javaClass.simpleName}: ${EvidenceSanitizer.sanitize(e.message.orEmpty()).take(160)}")
                }
            }
        }
        if (queue.isNotEmpty() && pages.size >= options.maxPages) events += WebsiteDiscoveryEventV1("", "PAGE_LIMIT", "سقف ${options.maxPages} صفحه تکمیل شد.")
        WebsiteDiscoveryResultV1(manifest.engagementId, started, System.currentTimeMillis(), pages, events, requests,
            listOf(
                "فقط HTTP GET بدون Cookie، Token، login یا فرم؛ درخواست‌ها به IP بررسی‌شده pin شدند.",
                "فقط hostname، port، path، زمان، test class و request budget داخل EngagementManifest مجاز بودند.",
                "redirectها، لینک‌های خارج از scope، مسیرهای ممنوع و مقصدهای IP غیرمجاز دنبال نشدند.",
                "محتوای خام صفحه ذخیره نمی‌شود؛ فقط hash، عنوان پاک‌سازی‌شده و هدرهای مجاز نگهداری می‌شوند.",
                "این قابلیت crawler محدود passive است؛ DAST، بررسی auth، API mutation، checkout و آزمون business logic اجرا نمی‌شود."
            ))
        }
    }

    /** Result of a single pinned HTTPS GET used only to read an ownership-proof file. */
    internal data class OwnershipProofFetchV1(val status: Int, val contentType: String, val body: String, val ip: String)

    /**
     * One pinned GET (DNS answer validated against the manifest, TLS hostname validated, no redirect followed, <= 8 KB).
     * HTTPS only: a proof served over plain HTTP can be forged by anyone on the network path.
     */
    internal fun fetchForOwnershipProof(urlText: String, manifest: WebsiteEngagementManifestV2): OwnershipProofFetchV1 {
        require(urlText.startsWith("https://", ignoreCase = true)) { "Ownership proof must be served over HTTPS." }
        val options = WebsiteDiscoveryOptionsV1(maxPages = 1, maxDepth = 0, maxBodyBytes = 8 * 1024)
        val r = fetchPinned(urlText, manifest, options)
        return OwnershipProofFetchV1(
            status = r.status,
            contentType = r.headers["content-type"].orEmpty().substringBefore(';').trim().lowercase(),
            body = r.body.toString(Charsets.UTF_8),
            ip = r.ip
        )
    }

    /** Result of one pinned passive GET (headers limited to the engine's allowlist plus location/content-type). */
    internal data class PassiveFetchV1(val status: Int, val headers: Map<String, String>, val body: String, val ip: String, val tls: TlsSessionInfoV1? = null)

    /** One pinned GET with the same DNS/IP/TLS gates as the crawler; redirects are never followed. */
    internal fun fetchPassive(urlText: String, manifest: WebsiteEngagementManifestV2, maxBodyBytes: Int = 64 * 1024): PassiveFetchV1 {
        val options = WebsiteDiscoveryOptionsV1(maxPages = 1, maxDepth = 0, maxBodyBytes = maxBodyBytes.coerceIn(8 * 1024, 256 * 1024))
        val r = fetchPinned(urlText, manifest, options)
        return PassiveFetchV1(r.status, r.headers, r.body.toString(Charsets.UTF_8), r.ip, r.tls)
    }

    private fun fetchPinned(urlText: String, manifest: WebsiteEngagementManifestV2, options: WebsiteDiscoveryOptionsV1): PinnedHttpResponseV1 {
        val uri = URI(urlText)
        val host = uri.host ?: error("Hostname missing")
        val port = if (uri.port >= 0) uri.port else if (uri.scheme.equals("https", true)) 443 else 80
        require(port in manifest.authorizedPorts) { "Port is outside the approved scope." }
        val resolved = InetAddress.getAllByName(bareHost(host)).distinctBy { it.hostAddress }
        require(resolved.isNotEmpty()) { "DNS resolution returned no address." }
        require(resolved.all { manifest.isResolvedAddressAllowed(it) }) {
            "حداقل یکی از IPهای resolve شده خارج از محدوده مجاز یا private/reserved بدون CIDR مجاز است؛ درخواست مسدود شد."
        }
        // Use only already-validated IP answers; never let Socket resolve the hostname a second time.
        // If one validated address refuses/times out, try the next validated one (bounded).
        var connected: Socket? = null
        var selected: InetAddress? = null
        var lastConnectError: Throwable? = null
        for (candidate in resolved.take(MAX_CONNECT_CANDIDATES)) {
            val attempt = Socket()
            try {
                attempt.connect(InetSocketAddress(candidate, port), options.connectTimeoutMs)
                connected = attempt
                selected = candidate
                break
            } catch (e: java.io.IOException) {
                runCatching { attempt.close() }
                lastConnectError = e
            }
        }
        val raw: Socket = connected ?: throw (lastConnectError ?: java.io.IOException("No validated address accepted a connection."))
        val chosen: InetAddress = selected ?: error("No validated address selected.")
        var managed: Socket = raw
        try {
            raw.soTimeout = options.readTimeoutMs
            var tlsInfo: TlsSessionInfoV1? = null
            val socket = if (uri.scheme.equals("https", true)) {
                val ssl = (SSLSocketFactory.getDefault() as SSLSocketFactory).createSocket(raw, bareHost(host), port, true) as SSLSocket
                managed = ssl
                val params: SSLParameters = ssl.sslParameters
                params.endpointIdentificationAlgorithm = "HTTPS"
                if (!bareHost(host).contains(':')) runCatching { params.serverNames = listOf(SNIHostName(bareHost(host))) }
                ssl.sslParameters = params
                ssl.soTimeout = options.readTimeoutMs
                ssl.startHandshake()
                tlsInfo = TlsSessionInfoV1.fromSession(ssl.session)
                ssl
            } else raw
            socket.use {
                val path = (uri.rawPath.ifBlank { "/" }) + (uri.rawQuery?.let { "?$it" } ?: "")
                val hostHeader = hostHeaderValue(host)
                val defaultPort = uri.scheme.equals("https", true) && port == 443 || uri.scheme.equals("http", true) && port == 80
                val request = buildString {
                    append("GET $path HTTP/1.1\r\n")
                    append("Host: $hostHeader${if (defaultPort) "" else ":$port"}\r\n")
                    append("User-Agent: ${SiteGuardBuildInfo.USER_AGENT}\r\n")
                    append("Accept: text/html,application/xhtml+xml;q=0.9\r\nAccept-Encoding: identity\r\n")
                    append("Range: bytes=0-${options.maxBodyBytes - 1}\r\nConnection: close\r\n\r\n")
                }
                socket.getOutputStream().apply { write(request.toByteArray(Charsets.US_ASCII)); flush() }
                val input = socket.getInputStream()
                val headerBytes = readHeaderBlock(input)
                val headerText = headerBytes.toString(Charsets.ISO_8859_1)
                val lines = headerText.split("\r\n")
                val status = Regex("^HTTP/\\d(?:\\.\\d)?\\s+(\\d{3})\\b", RegexOption.IGNORE_CASE)
                    .find(lines.firstOrNull().orEmpty())?.groupValues?.get(1)?.toIntOrNull() ?: error("Invalid HTTP status line")
                val headers = linkedMapOf<String, String>()
                lines.drop(1).forEach { line ->
                    val colon = line.indexOf(':')
                    if (colon > 0) {
                        val name = line.substring(0, colon).trim().lowercase()
                        if (name in SAFE_RESPONSE_HEADERS || name in setOf("location", "content-type", "content-length", "transfer-encoding")) {
                            headers[name] = line.substring(colon + 1).trim().take(2_000)
                        }
                    }
                }
                val body = if (isChunked(headers["transfer-encoding"])) readChunkedBody(input, options.maxBodyBytes)
                else readBoundedBody(input, options.maxBodyBytes)
                return PinnedHttpResponseV1(status, headers, body, chosen.hostAddress.orEmpty(), tlsInfo)
            }
        } catch (t: Throwable) {
            runCatching { managed.close() }; runCatching { raw.close() }
            throw t
        }
    }

    private fun readHeaderBlock(input: InputStream): ByteArray {
        val out = ByteArrayOutputStream()
        var matched = 0
        val delimiter = byteArrayOf(13, 10, 13, 10)
        while (out.size() < 32_768) {
            val b = input.read()
            if (b < 0) break
            out.write(b)
            matched = when {
                b == delimiter[matched].toInt() -> matched + 1
                b == 13 -> 1
                else -> 0
            }
            if (matched == delimiter.size) return out.toByteArray().copyOf(out.size() - 4)
        }
        error("HTTP response headers are incomplete or exceed 32 KB.")
    }

    /** java.net.URI keeps brackets on IPv6 literals; DNS/SNI/TLS need the bare form, the Host header needs brackets once. */
    internal fun bareHost(host: String): String = host.removePrefix("[").removeSuffix("]")

    internal fun hostHeaderValue(host: String): String {
        val bare = bareHost(host)
        return if (bare.contains(':')) "[$bare]" else bare
    }

    internal fun isChunked(transferEncoding: String?): Boolean =
        transferEncoding.orEmpty().lowercase().split(',').map { it.trim() }.contains("chunked")

    private fun readLineBounded(input: InputStream, max: Int = 1_024): String? {
        val sb = StringBuilder()
        while (sb.length < max) {
            val b = input.read()
            if (b < 0) return if (sb.isEmpty()) null else sb.toString()
            if (b == 10) return sb.toString().trimEnd('\r')
            sb.append(b.toChar())
        }
        error("Chunk header line is too long.")
    }

    /** Decodes `Transfer-Encoding: chunked`, stopping at the last chunk or at [limit] decoded bytes. Trailers are ignored. */
    internal fun readChunkedBody(input: InputStream, limit: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val buffer = ByteArray(4096)
        while (out.size() < limit) {
            val line = readLineBounded(input) ?: break
            val sizeText = line.substringBefore(';').trim()
            if (sizeText.isEmpty()) continue
            val size = sizeText.toIntOrNull(16) ?: error("Invalid chunk size.")
            if (size < 0) error("Invalid chunk size.")
            if (size == 0) break
            var remaining = size
            while (remaining > 0 && out.size() < limit) {
                val count = input.read(buffer, 0, minOf(buffer.size, remaining, limit - out.size()))
                if (count < 0) return out.toByteArray()
                out.write(buffer, 0, count)
                remaining -= count
            }
            if (out.size() >= limit) break
            readLineBounded(input) // CRLF that terminates the chunk data
        }
        return out.toByteArray()
    }

    private fun readBoundedBody(input: InputStream, limit: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val buffer = ByteArray(4096)
        while (out.size() < limit) {
            val count = input.read(buffer, 0, minOf(buffer.size, limit - out.size()))
            if (count < 0) break
            out.write(buffer, 0, count)
        }
        return out.toByteArray()
    }

    private fun extractLinks(html: String, baseUrl: String): List<String> {
        val base = URI(baseUrl)
        val rootHost = base.host.lowercase()
        val found = linkedSetOf<String>()
        val pattern = Regex("(?is)<a\\b[^>]*?\\bhref\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s>]+))")
        pattern.findAll(html.take(256 * 1024)).forEach { match ->
            val raw = (1..3).map { match.groups[it]?.value }.firstOrNull { !it.isNullOrBlank() }?.trim() ?: return@forEach
            if (raw.startsWith("#") || raw.startsWith("javascript:", true) || raw.startsWith("mailto:", true) || raw.startsWith("data:", true)) return@forEach
            val resolved = runCatching { base.resolve(raw).normalize() }.getOrNull() ?: return@forEach
            if (resolved.host?.lowercase() != rootHost || resolved.scheme?.lowercase() !in setOf("http", "https")) return@forEach
            if (resolved.rawUserInfo != null || resolved.rawPath.orEmpty().contains("\\") || resolved.rawPath.orEmpty().split('/').any { it == ".." || it == "." }) return@forEach
            // Avoid query-driven crawls; they can trigger expensive or stateful application paths.
            val cleaned = URI(resolved.scheme, null, resolved.host, resolved.port, resolved.path.ifBlank { "/" }, null, null).toString()
            normalizeUrl(cleaned)?.let(found::add)
        }
        return found.toList().take(100)
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    private const val MAX_CONNECT_CANDIDATES = 3
    private val SAFE_RESPONSE_HEADERS = setOf("server", "strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy", "cache-control", "vary")
}

/** CIDR-aware resolved-address gate; parsing is numeric-only and never performs a hostname lookup. */
fun WebsiteEngagementManifestV2.isResolvedAddressAllowed(address: InetAddress): Boolean {
    val inExplicitRange = authorizedIpRanges.any { cidr -> CidrMatcherV1.contains(cidr, address) }
    if (AddressPolicy.isNonPublic(address)) return inExplicitRange
    return authorizedIpRanges.isEmpty() || inExplicitRange
}

object CidrMatcherV1 {
    fun isValidCidr(cidr: String): Boolean = runCatching {
        val parts = cidr.trim().split('/')
        if (parts.size != 2) return false
        val address = parseIpLiteral(parts[0]) ?: return false
        val prefix = parts[1].toIntOrNull() ?: return false
        prefix in 0..(address.address.size * 8)
    }.getOrDefault(false)

    fun contains(cidr: String, address: InetAddress): Boolean = runCatching {
        val parts = cidr.trim().split('/')
        if (parts.size != 2) return false
        val network = parseIpLiteral(parts[0])?.address ?: return false
        val target = address.address
        if (network.size != target.size) return false
        val prefix = parts[1].toIntOrNull() ?: return false
        if (prefix !in 0..(network.size * 8)) return false
        val fullBytes = prefix / 8
        val remainingBits = prefix % 8
        for (i in 0 until fullBytes) if (network[i] != target[i]) return false
        if (remainingBits > 0) {
            val mask = (0xff shl (8 - remainingBits)) and 0xff
            if ((network[fullBytes].toInt() and 0xff and mask) != (target[fullBytes].toInt() and 0xff and mask)) return false
        }
        true
    }.getOrDefault(false)

    /** Numeric-only parser: never accepts hostnames and never performs DNS resolution. */
    private fun parseIpLiteral(raw: String): InetAddress? = runCatching {
        val value = raw.trim()
        require(value.isNotEmpty() && !value.contains('%'))
        if (value.contains(':')) {
            require(value.matches(Regex("[0-9A-Fa-f:.]+")))
            val parsed = InetAddress.getByName(value)
            require(parsed.address.size == 16)
            parsed
        } else {
            val octets = value.split('.')
            require(octets.size == 4)
            val bytes = octets.map { part ->
                require(part.isNotEmpty() && part.length <= 3 && part.all(Char::isDigit))
                val number = part.toInt()
                require(number in 0..255)
                number.toByte()
            }.toByteArray()
            InetAddress.getByAddress(bytes)
        }
    }.getOrNull()
}
