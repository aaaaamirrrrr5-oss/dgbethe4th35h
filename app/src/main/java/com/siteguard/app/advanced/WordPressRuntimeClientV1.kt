package com.siteguard.app.advanced

import java.net.HttpURLConnection
import java.net.URL
import java.net.IDN
import java.net.InetAddress
import java.util.Base64
import com.siteguard.app.core.AddressPolicy

/** Read-only WordPress/WooCommerce REST client. It exposes only a fixed list of GET routes. */
data class WordPressEndpointResultV1(
    val route: String,
    val httpStatus: Int?,
    val success: Boolean,
    val summary: String,
    val itemCount: Int? = null
)

data class WordPressRuntimeReportV1(
    val baseUrl: String,
    val siteHost: String,
    val checkedAtEpochMs: Long,
    val endpoints: List<WordPressEndpointResultV1>,
    val limitations: List<String>
) {
    val isWordPressReachable: Boolean get() = endpoints.any { it.route == "users/me" && it.success }
    val isWooCommerceAvailable: Boolean get() = endpoints.any { it.route == "wc/v3/system_status" && it.success }
}

class WordPressReadOnlyClientV1(
    private val connectTimeoutMs: Int = 10_000,
    private val readTimeoutMs: Int = 12_000,
    private val maxResponseBytes: Int = 1_500_000
) {
    private val routes = listOf(
        "wp/v2/users/me?context=edit",
        "wp/v2/settings",
        "wp/v2/plugins",
        "wp/v2/themes",
        "wc/v3/system_status"
    )

    fun inspect(
        baseUrl: String,
        username: String,
        applicationPassword: String,
        allowPrivateNetwork: Boolean = false,
        connectionFactory: ((URL) -> HttpURLConnection)? = null
    ): WordPressRuntimeReportV1 {
        val base = normalizeBase(baseUrl)
        require(username.isNotBlank() && username.length <= 128) { "WordPress username is required" }
        require(applicationPassword.isNotBlank() && applicationPassword.length <= 256) { "WordPress Application Password is required" }
        val parsed = URL(base)
        val host = parsed.host.lowercase()
        val addressSet = InetAddress.getAllByName(host)
        require(addressSet.isNotEmpty()) { "WordPress host did not resolve" }
        if (!allowPrivateNetwork) require(addressSet.all { isPublicAddress(it) }) {
            "WordPress host resolves to a private/reserved IP; enable private-network mode only for your own staging site"
        }
        val auth = "Basic " + Base64.getEncoder().encodeToString("$username:${applicationPassword.replace(" ", "")}".toByteArray(Charsets.UTF_8))
        val results = mutableListOf<WordPressEndpointResultV1>()
        for (route in routes) {
            val endpointUrl = URL(base.trimEnd('/') + "/wp-json/" + route)
            require(endpointUrl.protocol == "https" && endpointUrl.host.equals(host, true)) { "WordPress route escaped the authorized HTTPS origin" }
            try {
                // Default transport: one DNS resolution, validated-address pinning, TLS verified BEFORE the Authorization
                // header is written. A caller-supplied factory (tests) keeps the legacy HttpURLConnection path.
                val (code, body) = if (connectionFactory != null) fetchViaConnection(endpointUrl, auth, connectionFactory, host, allowPrivateNetwork)
                    else fetchPinned(parsed, endpointUrl, auth, allowPrivateNetwork)
                val parsedBody = if (body.isNotBlank()) runCatching { MiniJsonV1.parse(body, maxChars = maxResponseBytes) }.getOrNull() else null
                val count = parsedBody as? List<*> ?: ((parsedBody as? Map<*, *>)?.get("plugins") as? List<*>)
                val summary = when {
                    code in 200..299 && route.endsWith("users/me?context=edit") -> "هویت کاربر احرازشده دریافت شد؛ جزئیات شخصی در گزارش ذخیره نمی‌شود."
                    code in 200..299 && route.endsWith("settings") -> "تنظیمات قابل‌خواندن دریافت شد؛ مقدارهای حساس حذف شدند."
                    code in 200..299 && route.endsWith("plugins") -> "فهرست افزونه‌ها دریافت شد."
                    code in 200..299 && route.endsWith("themes") -> "فهرست قالب‌ها دریافت شد."
                    code in 200..299 && route.startsWith("wc/") -> "وضعیت سیستم WooCommerce دریافت شد."
                    code == 401 || code == 403 -> "احراز هویت یا مجوز خواندن این مسیر کافی نیست."
                    code == 404 -> "این مسیر در نسخه/تنظیمات فعلی در دسترس نیست."
                    code in 300..399 -> "سرور Redirect برگرداند؛ دنبال‌کردن Redirect عمداً غیرفعال است."
                    else -> "پاسخ دریافت شد؛ برای جلوگیری از نگهداری داده خام فقط کد وضعیت ثبت شد."
                }
                results += WordPressEndpointResultV1(route, code, code in 200..299, summary, count?.size)
            } catch (e: Exception) {
                results += WordPressEndpointResultV1(route, null, false, "درخواست ناموفق: ${safeError(e)}")
            }
        }
        return WordPressRuntimeReportV1(
            base, host, System.currentTimeMillis(), results,
            listOf(
                "همه درخواست‌ها فقط GET هستند؛ هیچ پست، سفارش، کاربر، تنظیم یا افزونه‌ای تغییر نمی‌کند.",
                "گذرواژه کاربردی فقط برای طول اجرای درخواست در حافظه نگه داشته می‌شود و ذخیره/لاگ نمی‌شود.",
                "در دسترس نبودن REST route می‌تواند ناشی از نسخه، capability، WAF یا افزونه‌های امنیتی باشد.",
                "این بررسی جایگزین تست مجاز role/capability، بررسی سرور یا تست پرداخت در sandbox نیست."
            )
        )
    }

    private fun fetchPinned(parsed: URL, endpointUrl: URL, auth: String, allowPrivateNetwork: Boolean): Pair<Int, String> {
        val response = com.siteguard.app.core.PinnedHttpsClientV1.get(
            host = parsed.host, port = if (parsed.port >= 0) parsed.port else 443, requestTarget = endpointUrl.file,
            extraHeaders = mapOf("Authorization" to auth), allowPrivateNetwork = allowPrivateNetwork,
            maxBodyBytes = maxResponseBytes, connectTimeoutMs = connectTimeoutMs, readTimeoutMs = readTimeoutMs
        )
        return response.status to response.body.toString(Charsets.UTF_8)
    }

    private fun fetchViaConnection(endpointUrl: URL, auth: String, factory: (URL) -> HttpURLConnection, host: String, allowPrivateNetwork: Boolean): Pair<Int, String> {
        // Re-validate resolution right before each authenticated request to narrow DNS-rebinding windows (fail closed).
        if (!allowPrivateNetwork) require(InetAddress.getAllByName(host).all { isPublicAddress(it) }) {
            "WordPress host now resolves to a private/reserved IP; request aborted before sending credentials"
        }
        val connection = factory(endpointUrl)
        try {
            connection.connectTimeout = connectTimeoutMs
            connection.readTimeout = readTimeoutMs
            connection.instanceFollowRedirects = false
            connection.requestMethod = "GET"
            connection.setRequestProperty("Authorization", auth)
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("User-Agent", "SiteGuard-Android/0.14.0 (WordPress read-only audit)")
            val code = connection.responseCode
            val stream = if (code in 200..299) connection.inputStream else connection.errorStream
            return code to stream?.use { readBounded(it, maxResponseBytes) }.orEmpty()
        } finally {
            connection.disconnect()
        }
    }

    private fun normalizeBase(raw: String): String {
        val input = raw.trim().removeSuffix("/")
        require(input.isNotBlank() && input.length <= 2_048 && !input.any { it.isWhitespace() || it.code < 0x20 })
        val candidate = if (input.startsWith("https://", true)) input else "https://$input"
        val url = URL(candidate)
        require(url.protocol == "https" && url.userInfo == null && url.query == null && url.ref == null && url.port in -1..65_535)
        val host = if (url.host.contains(":")) url.host.trim('[', ']') else IDN.toASCII(url.host, IDN.USE_STD3_ASCII_RULES)
        require(host.isNotBlank() && url.path !in setOf("/wp-json", "/wp-json/")) { "Enter the site's origin, not a REST endpoint" }
        require(url.path.split('/').none { it == ".." || it == "." } && !url.path.contains('%')) { "WordPress base path is ambiguous" }
        // Preserve subdirectory installations, e.g. https://example.test/blog.
        return "https://${if (host.contains(':')) "[$host]" else host}${if (url.port >= 0) ":${url.port}" else ""}${url.path.trimEnd('/') }"
    }

    private fun readBounded(input: java.io.InputStream, max: Int): String {
        val out = java.io.ByteArrayOutputStream(); val buf = ByteArray(8_192); var total = 0
        while (total < max) { val n = input.read(buf, 0, minOf(buf.size, max - total)); if (n < 0) break; total += n; out.write(buf, 0, n) }
        return out.toString("UTF-8")
    }

    private fun safeError(e: Exception): String = when (e) {
        is java.net.SocketTimeoutException -> "مهلت اتصال تمام شد"
        is javax.net.ssl.SSLException -> "اعتبارسنجی TLS ناموفق بود"
        else -> (e.message ?: e.javaClass.simpleName).take(140).replace(Regex("(?i)(authorization|password|secret|token)\\s*[:=]\\s*\\S+"), "$1=[redacted]")
    }

    private fun isPublicAddress(address: InetAddress): Boolean = !AddressPolicy.isNonPublic(address)
}
