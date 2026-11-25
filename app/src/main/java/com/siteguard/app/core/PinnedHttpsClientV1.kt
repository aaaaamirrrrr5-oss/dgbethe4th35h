package com.siteguard.app.core

import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.ConnectException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NoRouteToHostException
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.Locale
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/** Result of a pinned HTTPS GET. Header names are lower-case; the body is already de-chunked and bounded. */
class PinnedHttpResponseV1(
    val status: Int,
    val headers: Map<String, List<String>>,
    val body: ByteArray,
    val bodyTruncated: Boolean,
    val connectedAddress: String
)

/**
 * Minimal HTTPS GET client that closes the DNS-rebinding gap of HttpURLConnection:
 * the host is resolved exactly once, every returned address is checked against [AddressPolicy], and the TCP
 * connection is opened to that already-validated address. SNI and certificate host-name verification still use the
 * real host name, TLS completes (and the certificate is verified) BEFORE any request bytes, headers or credentials
 * are written, redirects are never followed, and header/body sizes are bounded.
 */
object PinnedHttpsClientV1 {
    private const val MAX_HEADER_BYTES = 32_768
    private const val MAX_LINE_BYTES = 8_192
    private const val MAX_CONNECT_ATTEMPTS = 3
    private val ipv4Literal = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")
    private val statusPattern = Regex("^HTTP/\\d(?:\\.\\d)?\\s+(\\d{3})\\b", RegexOption.IGNORE_CASE)

    fun get(
        host: String,
        port: Int,
        requestTarget: String,
        extraHeaders: Map<String, String> = emptyMap(),
        allowPrivateNetwork: Boolean = false,
        maxBodyBytes: Int = 512 * 1024,
        connectTimeoutMs: Int = 8_000,
        readTimeoutMs: Int = 10_000,
        resolver: (String) -> List<InetAddress> = { name -> InetAddress.getAllByName(name).toList() }
    ): PinnedHttpResponseV1 {
        val asciiHost = requireNotNull(canonicalHost(host)) { "Invalid host" }
        require(port in 1..65_535) { "Invalid port" }
        require(maxBodyBytes in 0..(8 * 1024 * 1024)) { "Invalid body limit" }
        require(
            requestTarget.startsWith("/") && requestTarget.length <= 2_048 &&
                requestTarget.none { it.code <= 0x20 || it.code >= 0x7f }
        ) { "Invalid request target" }
        for ((name, value) in extraHeaders) {
            require(name.isNotEmpty() && name.none { it.code < 0x21 || it.code > 0x7e || it == ':' }) { "Invalid header name" }
            require(value.none { it == '\r' || it == '\n' || it.code == 0 }) { "Invalid header value" }
        }
        val addresses = resolver(asciiHost).distinctBy { it.hostAddress }
        require(addresses.isNotEmpty()) { "Host did not resolve" }
        if (!allowPrivateNetwork) {
            require(addresses.none { AddressPolicy.isNonPublic(it) }) { "Host resolves to a private/reserved address" }
        }
        var lastError: IOException? = null
        for (candidate in addresses.take(MAX_CONNECT_ATTEMPTS)) {
            val raw = Socket()
            try {
                raw.connect(InetSocketAddress(candidate, port), connectTimeoutMs)
            } catch (e: IOException) {
                runCatching { raw.close() }
                val connectLevel = e is ConnectException || e is NoRouteToHostException || e is SocketTimeoutException
                if (!connectLevel) throw e
                lastError = e
                continue
            }
            return exchange(raw, asciiHost, port, requestTarget, extraHeaders, maxBodyBytes, readTimeoutMs, candidate.hostAddress.orEmpty())
        }
        throw lastError ?: IOException("Connection failed")
    }

    private fun exchange(
        raw: Socket, host: String, port: Int, target: String, extra: Map<String, String>,
        maxBody: Int, readTimeoutMs: Int, address: String
    ): PinnedHttpResponseV1 {
        var active: Socket = raw
        try {
            raw.soTimeout = readTimeoutMs
            val ssl = (SSLSocketFactory.getDefault() as SSLSocketFactory).createSocket(raw, host, port, true) as SSLSocket
            active = ssl
            val parameters = ssl.sslParameters
            parameters.endpointIdentificationAlgorithm = "HTTPS"
            if (!host.contains(':') && !ipv4Literal.matches(host)) {
                runCatching { parameters.serverNames = listOf(SNIHostName(host)) }
            }
            ssl.sslParameters = parameters
            ssl.soTimeout = readTimeoutMs
            ssl.startHandshake() // certificate chain and host name are verified here, before anything is sent
            val hostHeader = if (host.contains(':')) "[$host]" else host
            val request = buildString {
                append("GET ").append(target).append(" HTTP/1.1\r\n")
                append("Host: ").append(hostHeader).append(if (port == 443) "" else ":$port").append("\r\n")
                append("User-Agent: ").append(SiteGuardBuildInfo.USER_AGENT).append("\r\n")
                append("Accept: application/json,text/html;q=0.9,*/*;q=0.5\r\n")
                append("Accept-Encoding: identity\r\n")
                for ((name, value) in extra) append(name).append(": ").append(value).append("\r\n")
                append("Connection: close\r\n\r\n")
            }
            val out = ssl.getOutputStream()
            out.write(request.toByteArray(Charsets.US_ASCII))
            out.flush()
            return readResponse(BufferedInputStream(ssl.getInputStream()), maxBody, address)
        } finally {
            runCatching { active.close() }
            runCatching { raw.close() }
        }
    }

    internal fun readResponse(stream: InputStream, maxBody: Int, address: String): PinnedHttpResponseV1 {
        val statusLine = readLine(stream, MAX_LINE_BYTES) ?: throw IOException("Empty HTTP response")
        val status = statusPattern.find(statusLine)?.groupValues?.get(1)?.toIntOrNull()
            ?: throw IOException("Invalid HTTP response")
        val headers = linkedMapOf<String, MutableList<String>>()
        var headerBytes = statusLine.length
        while (true) {
            val current = readLine(stream, MAX_LINE_BYTES) ?: break
            headerBytes += current.length + 2
            require(headerBytes <= MAX_HEADER_BYTES) { "Response headers exceed limit" }
            if (current.isEmpty()) break
            val colon = current.indexOf(':')
            if (colon <= 0) continue
            headers.getOrPut(current.substring(0, colon).trim().lowercase(Locale.ROOT)) { mutableListOf() }
                .add(current.substring(colon + 1).trim())
        }
        val noBody = status in 100..199 || status == 204 || status == 304
        val chunked = headers["transfer-encoding"].orEmpty().any { it.contains("chunked", ignoreCase = true) }
        val declaredLength = headers["content-length"]?.firstOrNull()?.trim()?.toLongOrNull()
        val body = ByteArrayOutputStream()
        var truncated = false
        if (!noBody) {
            truncated = if (chunked) readChunked(stream, body, maxBody) else readIdentity(stream, body, maxBody, declaredLength)
        }
        return PinnedHttpResponseV1(status, headers, body.toByteArray(), truncated, address)
    }

    private fun readLine(stream: InputStream, maxBytes: Int): String? {
        val out = ByteArrayOutputStream()
        var sawAny = false
        while (true) {
            val next = stream.read()
            if (next < 0) break
            sawAny = true
            if (next == '\n'.code) break
            if (next != '\r'.code) out.write(next)
            require(out.size() <= maxBytes) { "Line too long" }
        }
        return if (sawAny) out.toString(Charsets.ISO_8859_1.name()) else null
    }

    /** Returns true when the body was cut at [maxBody]. */
    private fun readIdentity(stream: InputStream, sink: ByteArrayOutputStream, maxBody: Int, declared: Long?): Boolean {
        val buffer = ByteArray(8_192)
        val limit = if (declared != null && declared >= 0) declared else Long.MAX_VALUE
        var total = 0L
        while (total < limit) {
            if (sink.size() >= maxBody) return true
            val want = minOf(buffer.size.toLong(), limit - total, (maxBody - sink.size()).toLong()).toInt()
            val n = stream.read(buffer, 0, want)
            if (n < 0) return false
            sink.write(buffer, 0, n)
            total += n
        }
        return false
    }

    /** Decodes Transfer-Encoding: chunked. Returns true when the body was cut at [maxBody]. */
    private fun readChunked(stream: InputStream, sink: ByteArrayOutputStream, maxBody: Int): Boolean {
        val buffer = ByteArray(8_192)
        while (true) {
            val sizeLine = readLine(stream, 256) ?: return false
            val size = sizeLine.substringBefore(';').trim().toLongOrNull(16) ?: throw IOException("Invalid chunk size")
            if (size < 0) throw IOException("Invalid chunk size")
            if (size == 0L) return false
            var remaining = size
            while (remaining > 0) {
                if (sink.size() >= maxBody) return true
                val want = minOf(buffer.size.toLong(), remaining, (maxBody - sink.size()).toLong()).toInt()
                val n = stream.read(buffer, 0, want)
                if (n < 0) return false
                sink.write(buffer, 0, n)
                remaining -= n
            }
            readLine(stream, 16) // CRLF that terminates the chunk
        }
    }
}
