package com.siteguard.app.advanced

import java.net.HttpURLConnection
import java.net.URL
import java.net.IDN
import java.net.InetAddress
import com.siteguard.app.core.AddressPolicy
import com.siteguard.app.core.PinnedHttpsClientV1

/** Bounded, same-origin passive GET review of a website's standard metadata/API description paths. */
data class WebSurfaceControlV1(val id: String, val severity: String, val title: String, val evidence: String, val recommendation: String)
data class WebSurfacePageV1(val path: String, val status: Int, val contentType: String, val bytesRead: Int)
data class WebSurfaceReportV1(
    val origin: String, val checkedAtEpochMs: Long, val pages: List<WebSurfacePageV1>,
    val controls: List<WebSurfaceControlV1>, val discoveredApiPaths: List<String>, val limitations: List<String>
)

class WebSurfaceAnalyzerV1(
    private val maxResponseBytes: Int = 512 * 1024,
    private val connectTimeoutMs: Int = 8_000,
    private val readTimeoutMs: Int = 10_000
) {
    private val paths = listOf("/", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/openapi.json", "/.well-known/openapi.json")

    fun assess(rawOrigin: String, allowPrivateNetwork: Boolean = false,
               connectionFactory: ((URL) -> HttpURLConnection)? = null): WebSurfaceReportV1 {
        val origin = canonicalOrigin(rawOrigin)
        val parsed = URL(origin); val host = parsed.host
        val ips = InetAddress.getAllByName(host)
        require(ips.isNotEmpty()) { "Host did not resolve" }
        if (!allowPrivateNetwork) require(ips.all { isPublic(it) }) { "Target resolves to a private/reserved address" }
        val pages = mutableListOf<WebSurfacePageV1>()
        val controls = mutableListOf<WebSurfaceControlV1>()
        val apiPaths = linkedSetOf<String>()
        var rootHeaders: Map<String, List<String>> = emptyMap()
        var rootObserved = false
        for (path in paths) {
            val target = URL(origin + path.removePrefix("/"))
            require(target.protocol == "https" && target.host.equals(host, true) && target.port == parsed.port)
            try {
                // Default transport: single DNS resolution + validated address pinning + TLS verified before sending.
                // A caller-supplied factory (tests) keeps the legacy HttpURLConnection path.
                val fetched = if (connectionFactory != null) fetchViaConnection(target, connectionFactory, host, allowPrivateNetwork)
                    else fetchPinned(parsed, path, allowPrivateNetwork)
                if (path == "/") { rootHeaders = fetched.headers; rootObserved = true }
                pages += WebSurfacePageV1(path, fetched.status, fetched.contentType.take(100), fetched.bytesRead)
                if (path.contains("openapi")) {
                    Regex("\"(/[^\" ]{1,300})\"\\s*:").findAll(fetched.body).take(300).forEach { apiPaths += it.groupValues[1] }
                }
            } catch (e: Exception) {
                pages += WebSurfacePageV1(path, -1, "", 0)
                controls += WebSurfaceControlV1("WEB-REQUEST-ERROR", "INFO", "مسیر قابل بررسی نبود: $path", e.javaClass.simpleName, "در دسترس‌بودن مسیر را به‌صورت دستی بررسی کنید؛ خطا معادل آسیب‌پذیری نیست.")
            }
        }
        fun header(name: String) = rootHeaders[name.lowercase()].orEmpty().joinToString("; ")
        val checks = listOf(
            Triple("strict-transport-security", "SECURITY-HEADER-HSTS", "Strict-Transport-Security"),
            Triple("content-security-policy", "SECURITY-HEADER-CSP", "Content-Security-Policy"),
            Triple("x-content-type-options", "SECURITY-HEADER-NOSNIFF", "X-Content-Type-Options"),
            Triple("referrer-policy", "SECURITY-HEADER-REFERRER", "Referrer-Policy"),
            Triple("permissions-policy", "SECURITY-HEADER-PERMISSIONS", "Permissions-Policy")
        )
        checks.forEach { (headerName, id, label) ->
            // Only claim a header is absent when the root response was actually observed.
            if (rootObserved && header(headerName).isBlank()) controls += WebSurfaceControlV1(id, "LOW", "هدر $label در پاسخ ریشه مشاهده نشد", "GET /; header absent", "سیاست مناسب را با توجه به نوع برنامه تنظیم کنید؛ نبود هدر به‌تنهایی اثبات exploit نیست.")
        }
        val csp = header("content-security-policy")
        if (csp.contains("unsafe-inline", true) || csp.contains("unsafe-eval", true)) {
            controls += WebSurfaceControlV1("SECURITY-CSP-WEAK", "MEDIUM", "CSP شامل unsafe-inline/unsafe-eval است", csp.take(240), "در صورت سازگاری، nonce/hash و حذف eval را بررسی کنید.")
        }
        val cors = header("access-control-allow-origin")
        val credentials = header("access-control-allow-credentials")
        if (cors == "*" && credentials.equals("true", true)) {
            controls += WebSurfaceControlV1("SECURITY-CORS-WILDCARD-CREDENTIALS", "HIGH", "ترکیب CORS wildcard و credentials در پاسخ دیده شد", "ACAO=*; ACAC=true", "تنظیمات CORS را به originهای مشخص محدود کنید؛ رفتار مرورگر و سایر پاسخ‌ها را هم بررسی کنید.")
        }
        val securityText = pages.firstOrNull { it.path == "/.well-known/security.txt" }
        if (securityText == null || securityText.status !in 200..299) {
            controls += WebSurfaceControlV1("SECURITY-TXT-MISSING", "INFO", "security.txt در مسیر استاندارد قابل دریافت نبود", "GET /.well-known/security.txt", "یک مسیر تماس امنیتی عمومی ایجاد کنید؛ نبود آن آسیب‌پذیری فنی محسوب نمی‌شود.")
        }
        return WebSurfaceReportV1(origin, System.currentTimeMillis(), pages, controls, apiPaths.toList(), listOf(
            "فقط شش درخواست GET هم‌مبدأ انجام شد؛ redirect و احراز هویت دنبال/ارسال نشد.",
            "OpenAPI فقط از مسیرهای ثابت استاندارد جست‌وجو شد؛ هیچ عملیات API اجرا یا schema دلخواهی crawl نشد.",
            "این بررسی DAST کامل، تست authorization، تست منطق کسب‌وکار یا آزمون بار نیست.",
            "هدرهای ارزیابی‌شده فقط از پاسخ GET / خوانده می‌شوند و ممکن است برای مسیرهای دیگر متفاوت باشند."
        ))
    }

    private class Fetched(val status: Int, val headers: Map<String, List<String>>, val contentType: String, val body: String, val bytesRead: Int)

    private fun fetchPinned(parsed: URL, path: String, allowPrivateNetwork: Boolean): Fetched {
        val response = PinnedHttpsClientV1.get(
            host = parsed.host, port = if (parsed.port >= 0) parsed.port else 443, requestTarget = path,
            allowPrivateNetwork = allowPrivateNetwork, maxBodyBytes = maxResponseBytes,
            connectTimeoutMs = connectTimeoutMs, readTimeoutMs = readTimeoutMs
        )
        val contentType = response.headers["content-type"]?.firstOrNull().orEmpty()
        return Fetched(response.status, response.headers, contentType, response.body.toString(Charsets.UTF_8), response.body.size)
    }

    private fun fetchViaConnection(target: URL, factory: (URL) -> HttpURLConnection, host: String, allowPrivateNetwork: Boolean): Fetched {
        // Re-validate resolution right before each request to narrow DNS-rebinding windows (fail closed).
        if (!allowPrivateNetwork) require(InetAddress.getAllByName(host).all { isPublic(it) }) { "Target now resolves to a private/reserved address" }
        val conn = factory(target)
        try {
            conn.connectTimeout = connectTimeoutMs; conn.readTimeout = readTimeoutMs
            conn.instanceFollowRedirects = false; conn.requestMethod = "GET"
            conn.setRequestProperty("Accept", "text/html,application/json,text/plain,*/*;q=0.5")
            conn.setRequestProperty("User-Agent", "SiteGuard-Android/0.14.0 (passive web surface audit)")
            val status = conn.responseCode
            val headers = conn.headerFields.filterKeys { it != null }.mapKeys { it.key.lowercase() }
            val (body, bytesRead) = (if (status in 200..299) conn.inputStream else conn.errorStream)?.use { readBounded(it) } ?: ("" to 0)
            return Fetched(status, headers, conn.contentType.orEmpty(), body, bytesRead)
        } finally { conn.disconnect() }
    }

    private fun canonicalOrigin(raw: String): String {
        val value = raw.trim().removeSuffix("/")
        val url = URL(if (value.startsWith("https://", true)) value else "https://$value")
        require(url.protocol == "https" && url.userInfo == null && url.query == null && url.ref == null)
        require(url.path.isBlank() || url.path == "/") { "Enter an origin, not a deep path" }
        val ascii = IDN.toASCII(url.host)
        return "https://$ascii${if (url.port > 0) ":${url.port}" else ""}/"
    }

    /** Reads at most [maxResponseBytes]; larger bodies are truncated (headers were already captured), never fatal. */
    private fun readBounded(input: java.io.InputStream): Pair<String, Int> {
        val out = java.io.ByteArrayOutputStream(); val buffer = ByteArray(8192); var total = 0
        while (total < maxResponseBytes) {
            val n = input.read(buffer, 0, minOf(buffer.size, maxResponseBytes - total)); if (n < 0) break
            total += n; out.write(buffer, 0, n)
        }
        return out.toString("UTF-8") to total
    }

    private fun isPublic(a: InetAddress) = !AddressPolicy.isNonPublic(a)
}
