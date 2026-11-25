package com.siteguard.app.core

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.util.Locale
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/** Finding states deliberately distinguish observed facts from heuristic leads. */
enum class Severity { CRITICAL, HIGH, MEDIUM, LOW, INFO }
enum class FindingStatus { CONFIRMED, PROBABLE, UNVERIFIED, INFORMATIONAL, FALSE_POSITIVE }

data class Finding(
    val id: String,
    val title: String,
    val severity: Severity,
    val description: String,
    val remediation: String,
    val confidence: String = "High",
    val evidence: String = "",
    val cwe: String = "",
    val status: FindingStatus = FindingStatus.UNVERIFIED,
    val affectedAsset: String = "",
    val exactLocation: String = "",
    val detectionMethod: String = "deterministic-rule",
    val toolVersion: String = SiteGuardBuildInfo.VERSION_NAME,
    val detectedAtEpochMs: Long = System.currentTimeMillis(),
    val businessImpact: String = "نیازمند ارزیابی متناسب با کاربرد دارایی است.",
    val exploitPrerequisites: String = "از شواهد فعلی مشخص نشده است.",
    val safeValidation: String = "بازبینی دستی تنظیمات و شواهد بدون اجرای payload.",
    val notTested: String = "آزمون بهره‌برداری یا تغییر داده انجام نشده است.",
    val verificationProcedure: String = "پس از اصلاح، همین کنترل غیرفعال و فقط‌خواندنی را دوباره اجرا کنید.",
    val expectedResult: String = "کنترل اصلاح‌شده در پاسخ یا سورس قابل مشاهده باشد.",
    val actualResult: String = "هنوز تست اصلاح انجام نشده است.",
    val residualRisk: String = "پوشش این قاعده محدود است و سایر مسیرها بررسی نشده‌اند."
)

data class ScanResult(
    val host: String,
    val findings: List<Finding>,
    val message: String,
    val httpStatus: Int? = null,
    val scannedAt: Long = System.currentTimeMillis(),
    val authorizationId: String = "",
    val connectedAddress: String = "",
    val coverageNotes: List<String> = listOf("فقط یک درخواست HTTP GET محدود به Range ارسال شد؛ redirect دنبال نشد.")
)

private data class HttpObservation(val status: Int, val headers: Map<String, List<String>>)

class ScanEngine {
    suspend fun scan(
        input: String,
        allowPrivateNetwork: Boolean = false,
        authorization: AuthorizationManifest? = null
    ): ScanResult = withTimeout(SCAN_DEADLINE_MS) {
        withContext(Dispatchers.IO) {
        currentCoroutineContext().ensureActive()
        val decision = ScopeEnforcer.validate(input, authorization)
        if (!decision.allowed) return@withContext ScanResult("", emptyList(), "بررسی متوقف شد: ${decision.reason}")
        val authorization = authorization
            ?: return@withContext ScanResult("", emptyList(), "مانیفست مجوز برای این بررسی لازم است.")
        if (authorization.allowPrivateNetwork != allowPrivateNetwork) {
            return@withContext ScanResult("", emptyList(), "تنظیم اجازه شبکه داخلی با مانیفست مجوز یکسان نیست.")
        }
        val url = runCatching { URL(decision.normalizedUrl) }.getOrNull()
            ?: return@withContext ScanResult("", emptyList(), "آدرس پس از کنترل محدوده معتبر نیست.")
        // DNS, SNI, certificate verification and the Host header must all use the ASCII (punycode) form of the host;
        // the raw URL host can be Unicode (IDN), which InetAddress/US-ASCII request encoding would mangle.
        val hostForDns = canonicalHost(url.host)
            ?: return@withContext ScanResult(url.host, emptyList(), "نام میزبان پس از کنترل محدوده معتبر نیست.", authorizationId = decision.authorizationId)
        var pinnedAddress = ""
        try {
            currentCoroutineContext().ensureActive()
            val addresses = InetAddress.getAllByName(hostForDns).distinctBy { it.hostAddress }
            currentCoroutineContext().ensureActive()
            if (addresses.isEmpty()) return@withContext ScanResult(url.host, emptyList(), "دامنه به IP تبدیل نشد.", authorizationId = decision.authorizationId)
            val privateAddresses = addresses.filter(AddressPolicy::isNonPublic)
            if (privateAddresses.isNotEmpty() && !authorization.allowPrivateNetwork) {
                return@withContext ScanResult(url.host, emptyList(), "هدف حداقل به یک IP خصوصی/رزروشده resolve شده است؛ این هدف در مجوز فعلی مجاز نیست.", authorizationId = decision.authorizationId)
            }
            val port = if (url.port >= 0) url.port else if (url.protocol.equals("https", true)) 443 else 80
            // Shared policy gate: host, port, test class, method, time window and every resolved IP are re-checked by SecurityPolicyEngineV1.
            val policyDenial = ScanPolicyBridgeV1.firstDenial(authorization, hostForDns, port, addresses)
            if (policyDenial != null) {
                return@withContext ScanResult(url.host, emptyList(), "موتور سیاست امنیتی اسکن را رد کرد: $policyDenial", authorizationId = decision.authorizationId)
            }
            // Request budget (maxRequests / requestsPerMinute) is enforced here, the one choke point every caller
            // (UI, queue run-now and WorkManager) goes through; previously queue tasks bypassed it.
            if (!AuthorizationBudget.consume(authorization)) {
                return@withContext ScanResult(url.host, emptyList(), "بودجه درخواست این مجوز به پایان رسیده یا محدودیت نرخ آن رعایت نشده است.", authorizationId = decision.authorizationId)
            }
            // Every resolved address has already passed scope, policy and private-range checks above. If the first one
            // cannot be reached (e.g. an AAAA record on a network without IPv6), fall back to the next validated address.
            // Only connection-level failures fall through; no HTTP request has been sent in that case, and TLS validation
            // failures are reported as results rather than retried.
            val candidates = addresses.take(MAX_CONNECT_ATTEMPTS)
            val connectTimeoutMs = if (candidates.size > 1) FALLBACK_CONNECT_TIMEOUT_MS else CONNECT_TIMEOUT_MS
            var selectedAddress = candidates.first()
            var firstObservation: HttpObservation? = null
            for ((index, candidate) in candidates.withIndex()) {
                currentCoroutineContext().ensureActive()
                selectedAddress = candidate
                pinnedAddress = candidate.hostAddress.orEmpty()
                try {
                    firstObservation = requestHeadersOnly(url, candidate, port, connectTimeoutMs)
                    break
                } catch (e: java.io.IOException) {
                    val connectLevel = e is java.net.ConnectException || e is java.net.NoRouteToHostException ||
                        e is java.net.SocketTimeoutException
                    if (!connectLevel || index == candidates.lastIndex) throw e
                }
            }
            val observation = requireNotNull(firstObservation)
            currentCoroutineContext().ensureActive()
            val findings = inspectResponse(url, observation)
            ScanResult(
                host = url.host,
                findings = findings,
                message = "بررسی غیرفعال پایان یافت؛ HTTP ${observation.status}. فقط پاسخ همان میزبان مجاز بررسی شد و redirect دنبال نشد.",
                httpStatus = observation.status,
                authorizationId = decision.authorizationId,
                connectedAddress = selectedAddress.hostAddress,
                coverageNotes = listOf(
                    "محدوده: ${url.protocol}://${url.host}:$port",
                    "روش: HTTP GET با Range: bytes=0-0؛ بدنه پاسخ خوانده نشد.",
                    "DNS در شروع resolve شد و اتصال به IP انتخاب‌شده pin شد.",
                    "redirect، crawl، brute force، exploit و تغییر داده انجام نشدند.",
                    "فقط سرآیندهای یک پاسخ بررسی شدند؛ این نتیجه ارزیابی جامع امنیت سایت نیست."
                )
            )
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (e: Exception) {
            val failedPort = if (url.port >= 0) url.port else if (url.protocol.equals("https", true)) 443 else 80
            val tlsFailure = if (url.protocol.equals("https", true)) TlsFailureClassifier.classify(e) else null
            if (tlsFailure != null) {
                return@withContext ScanResult(
                    host = url.host,
                    findings = listOf(TlsFailureClassifier.toFinding(url.host, failedPort, tlsFailure)),
                    message = "دست‌دهی TLS با خطای اعتبارسنجی متوقف شد (${tlsFailure.kind.name}); هیچ پاسخ HTTP دریافت نشد.",
                    authorizationId = decision.authorizationId,
                    connectedAddress = pinnedAddress,
                    coverageNotes = listOf(
                        "محدوده: ${url.protocol}://${url.host}:$failedPort",
                        "DNS در شروع resolve شد و اتصال به IP انتخاب‌شده pin شد.",
                        "خطای TLS به‌عنوان مشاهده ثبت شد؛ علت (سرور، ساعت دستگاه، رهگیری شبکه یا CA سفارشی) باید از شبکه دیگری تأیید شود.",
                        "هدرها، کوکی‌ها و محتوا بررسی نشدند چون پاسخ HTTP دریافت نشد.",
                        "redirect، crawl، brute force، exploit و تغییر داده انجام نشدند."
                    )
                )
            }
            ScanResult(
                host = url.host,
                findings = emptyList(),
                message = "اتصال یا بررسی ناموفق بود: ${e.javaClass.simpleName}. هیچ مقصد redirect یا میزبان کشف‌شده‌ای دنبال نشد.",
                authorizationId = decision.authorizationId,
                coverageNotes = listOf("درخواست با خطا متوقف شد؛ خطا به‌عنوان یافته امنیتی ثبت نشده است.")
            )
        }
        }
    }

    companion object {
        // Bounds DNS+connect+TLS+header work; socket connect/read phases each have their own 8s cap.
        const val SCAN_DEADLINE_MS = 26_000L
        private const val MAX_CONNECT_ATTEMPTS = 3
        private const val CONNECT_TIMEOUT_MS = 8_000
        // 3 attempts x 5s + one 8s read phase stays inside SCAN_DEADLINE_MS.
        private const val FALLBACK_CONNECT_TIMEOUT_MS = 5_000

        /**
         * The request line is written as US-ASCII. Any non-ASCII character in the path/query (already validated in its
         * Unicode form) is percent-encoded as UTF-8 so it is sent as the same resource instead of being replaced by '?'.
         * ASCII characters, including existing %XX escapes, are left untouched.
         */
        internal fun asciiRequestTarget(file: String): String = buildString {
            for (byte in file.toByteArray(Charsets.UTF_8)) {
                val value = byte.toInt() and 0xff
                if (value < 0x80) append(value.toChar()) else append('%').append("%02X".format(value))
            }
        }
    }

    /** Connects to the exact DNS answer already checked, preventing a second hostname resolution at connect time. */
    private fun requestHeadersOnly(url: URL, address: InetAddress, port: Int, connectTimeoutMs: Int): HttpObservation {
        val asciiHost = canonicalHost(url.host) ?: error("نام میزبان معتبر نیست.")
        val rawSocket = Socket()
        var managedSocket: Socket = rawSocket
        try {
            rawSocket.connect(InetSocketAddress(address, port), connectTimeoutMs)
            rawSocket.soTimeout = 8_000
            val activeSocket = if (url.protocol.equals("https", true)) {
                val host = asciiHost
                val ssl = (SSLSocketFactory.getDefault() as SSLSocketFactory)
                    .createSocket(rawSocket, host, port, true) as SSLSocket
                managedSocket = ssl
                val parameters: SSLParameters = ssl.sslParameters
                parameters.endpointIdentificationAlgorithm = "HTTPS"
                if (!host.contains(':') && !host.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$"))) {
                    runCatching { parameters.serverNames = listOf(SNIHostName(host)) }
                }
                ssl.sslParameters = parameters
                ssl.soTimeout = 8_000
                ssl.startHandshake()
                ssl
            } else rawSocket

            activeSocket.use { active ->
                val hostHeader = if (asciiHost.contains(':')) "[$asciiHost]" else asciiHost
                val defaultPort = (url.protocol.equals("https", true) && port == 443) || (url.protocol.equals("http", true) && port == 80)
                val target = asciiRequestTarget((url.file.takeIf { it.isNotBlank() } ?: "/").let { if (it.startsWith("?")) "/$it" else it })
                val request = buildString {
                    append("GET $target HTTP/1.1\r\n")
                    append("Host: $hostHeader${if (defaultPort) "" else ":$port"}\r\n")
                    append("User-Agent: ${SiteGuardBuildInfo.USER_AGENT}\r\n")
                    append("Accept: text/html,application/json;q=0.9,*/*;q=0.5\r\n")
                    append("Accept-Encoding: identity\r\n")
                    append("Range: bytes=0-0\r\n")
                    append("Connection: close\r\n\r\n")
                }
                active.getOutputStream().apply { write(request.toByteArray(Charsets.US_ASCII)); flush() }
                return readResponseHeaders(active.getInputStream())
            }
        } catch (error: Throwable) {
            runCatching { managedSocket.close() }
            runCatching { rawSocket.close() }
            throw error
        }
    }

    private fun readResponseHeaders(input: InputStream): HttpObservation {
        val stream = BufferedInputStream(input)
        var consumed = 0
        fun line(): String {
            val out = ByteArrayOutputStream()
            while (true) {
                val next = stream.read()
                if (next < 0) break
                consumed++
                require(consumed <= 32_768) { "پاسخ هدر از سقف ۳۲ کیلوبایت عبور کرد." }
                if (next == '\n'.code) break
                if (next != '\r'.code) out.write(next)
                require(out.size() <= 8_192) { "طول یک هدر غیرعادی است." }
            }
            return out.toString(Charsets.ISO_8859_1.name())
        }
        val statusLine = line()
        val status = Regex("^HTTP/\\d(?:\\.\\d)?\\s+(\\d{3})\\b", RegexOption.IGNORE_CASE)
            .find(statusLine)?.groupValues?.get(1)?.toIntOrNull()
            ?: error("پاسخ HTTP معتبر دریافت نشد.")
        val headers = linkedMapOf<String, MutableList<String>>()
        while (true) {
            val current = line()
            if (current.isEmpty()) break
            val colon = current.indexOf(':')
            if (colon <= 0) continue
            val name = current.substring(0, colon).trim().lowercase(Locale.ROOT)
            val value = current.substring(colon + 1).trim()
            headers.getOrPut(name) { mutableListOf() }.add(value)
        }
        return HttpObservation(status, headers)
    }

    private fun inspectResponse(url: URL, response: HttpObservation): List<Finding> {
        val headers = response.headers
        fun header(name: String) = headers[name.lowercase(Locale.ROOT)]?.firstOrNull()
        val findings = mutableListOf<Finding>()
        fun add(
            id: String, title: String, severity: Severity, description: String, fix: String,
            evidence: String = "", cwe: String = "", status: FindingStatus = FindingStatus.UNVERIFIED
        ) {
            findings += Finding(
                id = id, title = title, severity = severity, description = description,
                remediation = fix, confidence = if (status == FindingStatus.CONFIRMED) "High" else "Medium",
                evidence = evidence, cwe = cwe, status = status,
                affectedAsset = url.host, exactLocation = "HTTP response headers",
                detectionMethod = "Pinned-IP passive HTTP header inspection",
                businessImpact = "ممکن است سطح سخت‌سازی یا افشای اطلاعات وب‌سایت را تحت تأثیر قرار دهد؛ اثر واقعی به معماری سایت بستگی دارد.",
                exploitPrerequisites = "برای موارد پیکربندی، بهره‌برداری صرفاً از روی فقدان هدر قابل اثبات نیست.",
                safeValidation = "هدر پاسخ را در مرورگر یا ابزار مشاهده درخواست بررسی کنید؛ payload ارسال نکنید.",
                notTested = "احراز هویت، منطق برنامه، مسیرهای API، پایگاه داده و بهره‌برداری آزمایش نشده‌اند."
            )
        }
        if (!url.protocol.equals("https", true)) {
            add("SG-HTTP-001", "ارتباط بدون HTTPS", Severity.HIGH,
                "پاسخ از HTTP دریافت شد؛ محرمانگی و یکپارچگی ترافیک توسط TLS محافظت نمی‌شود.",
                "TLS معتبر فعال کنید و HTTP را با تنظیم کنترل‌شده به HTTPS هدایت کنید.", "scheme=${url.protocol}", "CWE-319", FindingStatus.CONFIRMED)
        } else if (header("strict-transport-security") == null) {
            add("SG-TLS-001", "هدر HSTS مشاهده نشد", Severity.MEDIUM,
                "در پاسخ مشاهده‌شده هدر HSTS وجود نداشت؛ این موضوع به‌تنهایی نقص TLS یا امکان حمله را اثبات نمی‌کند.",
                "پس از اطمینان از پشتیبانی کامل HTTPS، HSTS را با max-age مناسب و در صورت آمادگی includeSubDomains فعال کنید.", "Strict-Transport-Security: absent", "CWE-693", FindingStatus.INFORMATIONAL)
        }
        if (header("content-security-policy") == null) {
            add("SG-HEAD-001", "Content-Security-Policy مشاهده نشد", Severity.MEDIUM,
                "سیاست CSP در پاسخ مشاهده‌شده وجود نداشت؛ این مورد اثبات XSS نیست.",
                "CSP را ابتدا در حالت Report-Only آزمایش و سپس با منابع مجاز محدود فعال کنید.", "Content-Security-Policy: absent", "CWE-693", FindingStatus.INFORMATIONAL)
        }
        if (header("x-content-type-options")?.contains("nosniff", true) != true) {
            add("SG-HEAD-002", "X-Content-Type-Options تنظیم نشده", Severity.LOW,
                "هدر nosniff مشاهده نشد.", "هدر X-Content-Type-Options: nosniff را اضافه کنید.", "X-Content-Type-Options: absent/invalid", "CWE-693", FindingStatus.INFORMATIONAL)
        }
        if (header("referrer-policy") == null) {
            add("SG-HEAD-003", "Referrer-Policy مشاهده نشد", Severity.LOW,
                "سیاست ارجاع‌دهنده مشخص نشده است.", "strict-origin-when-cross-origin را متناسب با نیاز برنامه تنظیم کنید.", "Referrer-Policy: absent", "CWE-200", FindingStatus.INFORMATIONAL)
        }
        if (header("permissions-policy") == null) {
            add("SG-HEAD-004", "Permissions-Policy مشاهده نشد", Severity.INFO,
                "محدودیت قابلیت‌های مرورگر از طریق این هدر مشاهده نشد.",
                "قابلیت‌های غیرضروری مانند camera، microphone و geolocation را محدود کنید.", "Permissions-Policy: absent", "CWE-693", FindingStatus.INFORMATIONAL)
        }
        header("server")?.takeIf(String::isNotBlank)?.let {
            add("SG-INFO-001", "اطلاعات Server افشا می‌شود", Severity.INFO,
                "پاسخ، هدر Server را اعلام می‌کند.", "در صورت امکان جزئیات نسخه و فناوری را حذف کنید.", "Server: ${it.take(120)}", "CWE-200", FindingStatus.INFORMATIONAL)
        }
        header("x-powered-by")?.takeIf(String::isNotBlank)?.let {
            add("SG-INFO-002", "هدر X-Powered-By مشاهده شد", Severity.INFO,
                "هدر پاسخ می‌تواند فناوری سمت سرور را افشا کند.", "هدر X-Powered-By را در تنظیمات برنامه یا وب‌سرور حذف کنید.", "X-Powered-By: ${it.take(120)}", "CWE-200", FindingStatus.INFORMATIONAL)
        }
        headers["set-cookie"].orEmpty().forEachIndexed { index, cookie ->
            val parts = cookie.substringAfter(';', "").lowercase(Locale.ROOT).split(';').map(String::trim)
            val name = cookie.substringBefore('=')
            if (url.protocol.equals("https", true) && "secure" !in parts) {
                add("SG-COOKIE-${index + 1}", "کوکی بدون Secure", Severity.MEDIUM,
                    "کوکی $name فاقد ویژگی Secure است.", "برای کوکی‌های حساس ویژگی Secure را فعال کنید.",
                    "Set-Cookie attributes checked for $name", "CWE-614", FindingStatus.INFORMATIONAL)
            }
            if ("httponly" !in parts) {
                add("SG-COOKIE-HTTP-${index + 1}", "کوکی بدون HttpOnly", Severity.LOW,
                    "کوکی $name فاقد ویژگی HttpOnly است.", "برای کوکی نشست که به JavaScript نیاز ندارد HttpOnly را فعال کنید.",
                    "Set-Cookie attributes checked for $name", "CWE-1004", FindingStatus.INFORMATIONAL)
            }
            if (parts.none { it.startsWith("samesite=") }) {
                add("SG-COOKIE-SAME-${index + 1}", "کوکی بدون SameSite", Severity.LOW,
                    "کوکی $name فاقد ویژگی SameSite است.", "SameSite=Lax یا Strict را متناسب با جریان ورود و پرداخت تنظیم کنید.",
                    "Set-Cookie attributes checked for $name", "CWE-1275", FindingStatus.INFORMATIONAL)
            }
        }
        if (response.status in 300..399) {
            add("SG-HTTP-REDIRECT", "پاسخ Redirect دریافت شد", Severity.INFO,
                "سرور پاسخ تغییر مسیر داد؛ SiteGuard عمداً مقصد را دنبال نکرد.",
                "مقصد Location را دستی بررسی کنید و مطمئن شوید در محدوده مجاز قرار دارد.",
                "HTTP ${response.status}; Location=${header("location") ?: "not supplied"}", status = FindingStatus.INFORMATIONAL)
        }
        if (findings.isEmpty()) {
            add("SG-INFO-003", "هشدار مشخصی در قواعد فعال پیدا نشد", Severity.INFO,
                "در این بررسی محدود موردی از قواعد فعال پیدا نشد؛ این نتیجه به معنی امن بودن کامل سایت نیست.",
                "برای پوشش بیشتر، سورس کد، وابستگی‌ها، API و پیکربندی سرور را بررسی کنید.",
                "HTTP ${response.status}", status = FindingStatus.INFORMATIONAL)
        }
        return findings
    }
}
