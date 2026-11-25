package com.siteguard.app.core

import java.net.ConnectException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap

/** Static review of network, SSH, DNS, TLS and identity configuration exports. */
object NetworkEnterpriseSecurityAnalyzer {
    fun analyze(files: Map<String, String>): List<Finding> {
        val out = mutableListOf<Finding>()
        files.forEach { (path, text) ->
            val lower = path.lowercase()
            val isNetConfig = lower.endsWith(".conf") || lower.endsWith(".cfg") || lower.endsWith(".ini") ||
                lower.endsWith(".zone") || lower.endsWith(".yaml") || lower.endsWith(".yml") ||
                lower.endsWith(".tf") || lower.endsWith(".json") || lower.contains("sshd_config")
            if (!isNetConfig) return@forEach
            text.lines().forEachIndexed { index, raw ->
                val line = raw.trim()
                val n = index + 1
                when {
                    Regex("(?i)^PasswordAuthentication\\s+yes\\b").containsMatchIn(line) -> add(out, "SG-NET-SSH-PASSWORD", path, n, "احراز هویت SSH با password فعال است", Severity.MEDIUM, "CWE-521", line, "برای حساب‌های مدیریتی، کلیدهای امن/SSO و MFA را ترجیح دهید؛ دسترسی SSH را با allowlist و کنترل نرخ محدود کنید.", "MFA، محدودیت شبکه و سایر روش‌های احراز هویت بررسی نشده‌اند.")
                    Regex("(?i)^PermitRootLogin\\s+yes\\b").containsMatchIn(line) -> add(out, "SG-NET-SSH-ROOT", path, n, "ورود مستقیم root از طریق SSH مجاز است", Severity.HIGH, "CWE-250", line, "PermitRootLogin را no یا prohibit-password متناسب با سیاست قرار دهید و مدیریت را با حساب کم‌اختیار انجام دهید.", "effective config ممکن است با includeها یا overrideها تغییر کند.")
                    Regex("(?i)^PermitEmptyPasswords\\s+yes\\b").containsMatchIn(line) -> add(out, "SG-NET-SSH-EMPTY", path, n, "رمز عبور خالی برای SSH مجاز شده است", Severity.CRITICAL, "CWE-521", line, "PermitEmptyPasswords را no کنید و سیاست اعتبارنامه امن را اعمال کنید.", "پیکربندی فعال سرویس و امکان login تست نشده‌اند.")
                    Regex("(?i)ssl_protocols?\\s+[^;]*(TLSv1(?:\\.0)?|TLSv1\\.1|SSLv[23])").containsMatchIn(line) -> add(out, "SG-NET-LEGACY-TLS", path, n, "پروتکل TLS قدیمی در پیکربندی ذکر شده است", Severity.MEDIUM, "CWE-326", line, "پروتکل‌های قدیمی را حذف و TLS 1.2/1.3 را بر اساس سازگاری سرویس فعال کنید.", "TLS handshake و cipherهای مؤثر روی endpoint تست نشده‌اند.")
                    Regex("(?i)allow-transfer\\s*\\{\\s*any\\s*;?\\s*}").containsMatchIn(line) -> add(out, "SG-NET-DNS-AXFR", path, n, "انتقال DNS zone برای any مجاز شده است", Severity.HIGH, "CWE-668", line, "انتقال zone را فقط به secondary DNSهای مشخص allowlist کنید و TSIG را در صورت پشتیبانی فعال کنید.", "هیچ درخواست AXFR ارسال نشده است.")
                    Regex("(?i)autoindex\\s+on\\s*;").containsMatchIn(line) -> add(out, "SG-NET-DIRECTORY-LISTING", path, n, "فهرست‌کردن دایرکتوری وب فعال است", Severity.LOW, "CWE-548", line, "autoindex را غیرفعال کنید مگر برای مسیر عمومی طراحی‌شده؛ فایل‌های backup/config را از web root خارج کنید.", "مسیر و قابلیت دسترسی endpoint بررسی نشده‌اند.")
                    Regex("(?i)Options\\s+.*Indexes").containsMatchIn(line) -> add(out, "SG-NET-APACHE-INDEXES", path, n, "Indexes در تنظیم Apache فعال است", Severity.LOW, "CWE-548", line, "Indexes را در directoryهای حساس غیرفعال کنید و دسترسی فایل‌ها را با allow/deny محدود کنید.", "VirtualHost و overrideهای مؤثر بررسی نشده‌اند.")
                    Regex("(?i)ServerTokens\\s+Full|ServerSignature\\s+On").containsMatchIn(line) -> add(out, "SG-NET-SERVER-BANNER", path, n, "افشای جزئیات banner سرور در config فعال است", Severity.INFO, "CWE-200", line, "جزئیات نسخه را در پاسخ‌های عمومی کاهش دهید و نسخه واقعی را به‌روز نگه دارید.", "هدر/صفحه خطای واقعی سرور دریافت نشده است.", FindingStatus.INFORMATIONAL)
                    Regex("""(?i)redirect_uris?["']?\s*[:=].*\*""").containsMatchIn(line) -> add(out, "SG-NET-OAUTH-WILDCARD-REDIRECT", path, n, "URI بازگشت OAuth شامل wildcard است", Severity.HIGH, "CWE-601", "OAuth redirect URI wildcard (raw value omitted)", "redirect URI را دقیق و scheme/host/path را allowlist کنید؛ PKCE و audience/issuer را در کلاینت و resource server اعتبارسنجی کنید.", "مقدار effective در identity provider و flow واقعی بررسی نشده است.")
                    Regex("""(?i)(mfa|required_mfa|requireMfa)["']?\s*[:=]\s*["']?(false|no|0)\b""").containsMatchIn(line) -> add(out, "SG-ID-MFA-DISABLED", path, n, "MFA در پیکربندی صریحاً غیرفعال است", Severity.HIGH, "CWE-308", line, "برای نقش‌های مدیریتی و دسترسی حساس MFA مقاوم به phishing را enforce کنید و حساب‌های emergency را جدا و پایش کنید.", "پوشش حساب‌ها، exceptionها و conditional access provider دیده نشده است.")
                    Regex("(?i)ldap://[^\\s\"']+").containsMatchIn(line) -> add(out, "SG-ID-LDAP-CLEAR", path, n, "LDAP بدون TLS در پیکربندی دیده شد", Severity.MEDIUM, "CWE-319", "ldap:// endpoint (hostname redacted)", "از LDAPS یا StartTLS معتبر استفاده کنید؛ certificate validation را غیرفعال نکنید.", "اتصال واقعی و امکان StartTLS در سرویس بررسی نشده است.")
                }
            }
            // JSON documents often place multiple controls on one physical line; evaluate identity controls independently.
            val mfaMatch = Regex("""(?i)(mfa|required_mfa|requireMfa)["']?\s*[:=]\s*["']?(false|no|0)\b""").find(text)
            if (mfaMatch != null) {
                val lineNumber = text.substring(0, mfaMatch.range.first).count { it == '\n' } + 1
                add(out, "SG-ID-MFA-DISABLED", path, lineNumber, "MFA در پیکربندی صریحاً غیرفعال است", Severity.HIGH, "CWE-308",
                    "کلید MFA با مقدار false/no/0؛ سایر محتویات خط حذف شد", "برای نقش‌های مدیریتی و دسترسی حساس MFA مقاوم به phishing را enforce کنید و حساب‌های emergency را جدا و پایش کنید.",
                    "پوشش حساب‌ها، exceptionها و conditional access provider دیده نشده است.")
            }
        }
        return out.distinctBy { it.id }
    }

    private fun add(out: MutableList<Finding>, id: String, path: String, line: Int, title: String, severity: Severity,
                    cwe: String, evidence: String, remediation: String, notTested: String,
                    status: FindingStatus = FindingStatus.PROBABLE) {
        out += Finding(
            id = "$id-L$line", title = title, severity = severity,
            description = "نشانه در فایل پیکربندی $path:$line پیدا شد؛ تنظیم مؤثر سرویس هنوز تأیید نشده است.",
            remediation = remediation, confidence = if (status == FindingStatus.INFORMATIONAL) "High" else "Low–Medium",
            evidence = EvidenceSanitizer.sanitize(evidence).take(160), cwe = cwe, status = status,
            affectedAsset = path, exactLocation = "$path:$line", detectionMethod = "Network/enterprise configuration deterministic review",
            businessImpact = "ممکن است سطح مواجهه سرویس یا ضعف کنترل هویت را افزایش دهد؛ اثر واقعی به config نهایی و محیط بستگی دارد.",
            exploitPrerequisites = "سرویس، rule precedence، ACL و دسترسی شبکه بررسی نشده‌اند.",
            safeValidation = "فقط از export/read-only config و تست محدود در محیط مجاز استفاده کنید.",
            notTested = notTested, verificationProcedure = "تغییر را در lab/staging اعمال و از client مجاز با تست مثبت/منفی بازبینی کنید.",
            expectedResult = "فقط پروتکل‌ها، حساب‌ها و منابع لازم در دسترس باشند."
        )
    }
}

/** Exact-IP, exact-port TCP connect check. It sends no application payload and performs no banner grabbing. */
data class NetworkScopeManifest(
    val authorizationId: String,
    val authorizedIpAddresses: Set<String>,
    val allowedPorts: Set<Int>,
    val allowPrivateNetwork: Boolean = false,
    val validUntilEpochMs: Long,
    val maxProbes: Int = 16,
    val authorizedTlsNames: Set<String> = emptySet()
)

enum class TcpProbeState { OPEN, CLOSED, FILTERED_OR_TIMEOUT, BLOCKED }
data class TcpProbeResult(
    val address: String, val port: Int, val state: TcpProbeState, val elapsedMs: Long,
    val reason: String, val authorizationId: String,
    val probableServiceHint: String = "نامشخص؛ فقط از روی پورت نیز سرویس قطعی نیست"
)

object CommonTcpServiceHints {
    private val services = mapOf(
        20 to "FTP-data", 21 to "FTP", 22 to "SSH", 23 to "Telnet", 25 to "SMTP",
        53 to "DNS/TCP", 80 to "HTTP", 110 to "POP3", 143 to "IMAP", 443 to "HTTPS",
        445 to "SMB", 587 to "SMTP submission", 993 to "IMAPS", 995 to "POP3S",
        1433 to "MSSQL", 3306 to "MySQL", 3389 to "RDP", 5432 to "PostgreSQL",
        5672 to "AMQP", 6379 to "Redis", 8080 to "HTTP-alt", 8443 to "HTTPS-alt",
        9200 to "Elasticsearch", 27017 to "MongoDB"
    )
    fun hint(port: Int): String = services[port]?.let { "احتمالی: $it بر اساس شماره پورت؛ نسخه تأیید نشده" }
        ?: "سرویس از روی پورت قابل حدس نیست؛ نسخه شناسایی نشده"
}

object NetworkTargetPolicy {
    fun parseNumericAddress(value: String): InetAddress? {
        val raw = value.trim()
        if (raw.isBlank() || raw.any { it.isWhitespace() } || raw.contains('%')) return null
        val isV4 = Regex("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$").matches(raw)
        val isV6 = raw.contains(':') && Regex("^[0-9A-Fa-f:.]+$").matches(raw)
        if (!isV4 && !isV6) return null
        if (isV4) {
            val octets = raw.split('.').map { it.toIntOrNull() ?: return null }
            if (octets.any { it !in 0..255 }) return null
            return runCatching { InetAddress.getByAddress(octets.map { it.toByte() }.toByteArray()) }.getOrNull()
        }
        return runCatching { InetAddress.getByName(raw) }.getOrNull()?.takeIf { it.address.size == 16 }
    }

    fun validate(addressText: String, port: Int, manifest: NetworkScopeManifest?, now: Long): Pair<InetAddress?, String?> {
        if (manifest == null || manifest.authorizationId.isBlank()) return null to "مجوز شبکه وجود ندارد."
        if (manifest.validUntilEpochMs < now || manifest.maxProbes !in 1..32) return null to "مجوز منقضی یا بودجه اسکن نامعتبر است."
        if (port !in manifest.allowedPorts || port !in 1..65535) return null to "پورت در allowlist دقیق مجاز نشده است."
        val address = parseNumericAddress(addressText) ?: return null to "فقط IP عددی صریح پذیرفته می‌شود؛ نام دامنه/DNS مجاز نیست."
        val canonical = address.hostAddress.substringBefore('%')
        val authorized = manifest.authorizedIpAddresses.mapNotNull { parseNumericAddress(it)?.hostAddress?.substringBefore('%') }.toSet()
        if (canonical !in authorized) return null to "IP خارج از محدوده دقیق مجوز است."
        if (!manifest.allowPrivateNetwork && AddressPolicy.isNonPublic(address)) return null to "IP خصوصی/رزروشده بدون مجوز شبکه داخلی رد شد."
        return address to null
    }
}

object NetworkProbeBudget {
    private data class Entry(var count: Int, val expiresAt: Long)
    private val usage = ConcurrentHashMap<String, Entry>()
    fun consume(manifest: NetworkScopeManifest, now: Long): Boolean {
        usage.entries.removeIf { it.value.expiresAt < now }
        val current = usage.computeIfAbsent(manifest.authorizationId) { Entry(0, manifest.validUntilEpochMs) }
        synchronized(current) {
            if (current.count >= manifest.maxProbes) return false
            current.count++
            return true
        }
    }
}

/** Validates a TLS certificate using the platform trust store and normal hostname/IP validation. */
data class TlsCertificateAssessment(
    val address: String, val port: Int, val subject: String, val issuer: String,
    val validFromEpochMs: Long, val validUntilEpochMs: Long, val sha256Fingerprint: String,
    val protocol: String, val cipherSuite: String, val authorizationId: String
)

class AuthorizedTlsCertificateProbe {
    fun inspect(addressText: String, port: Int, manifest: NetworkScopeManifest?, timeoutMs: Int = 1500,
                now: Long = System.currentTimeMillis(), serverName: String? = null): Result<TlsCertificateAssessment> {
        require(timeoutMs in 200..1500) { "TLS timeout خارج محدوده ایمن است." }
        val (address, failure) = NetworkTargetPolicy.validate(addressText, port, manifest, now)
        require(failure == null && address != null) { failure ?: "هدف مجاز نیست." }
        val auth = manifest!!
        val normalizedServerName = serverName?.trim()?.takeIf { it.isNotBlank() }?.let(::canonicalHost)
        if (!serverName.isNullOrBlank()) {
            require(normalizedServerName != null && normalizedServerName in auth.authorizedTlsNames.mapNotNull(::canonicalHost)) {
                "نام TLS در محدوده دقیق مجوز ثبت نشده است."
            }
        }
        val peerIdentity = normalizedServerName ?: address.hostAddress
        require(NetworkProbeBudget.consume(auth, now)) { "بودجه probe مجاز تکمیل شده است." }
        val started = Socket()
        try {
            started.connect(InetSocketAddress(address, port), timeoutMs)
            started.soTimeout = timeoutMs
            val factory = javax.net.ssl.SSLSocketFactory.getDefault() as javax.net.ssl.SSLSocketFactory
            val tls = factory.createSocket(started, peerIdentity, port, true) as javax.net.ssl.SSLSocket
            tls.use { socket ->
                socket.soTimeout = timeoutMs
                val params = socket.sslParameters
                params.endpointIdentificationAlgorithm = "HTTPS"
                if (normalizedServerName != null && NetworkTargetPolicy.parseNumericAddress(normalizedServerName) == null) {
                    params.serverNames = listOf(javax.net.ssl.SNIHostName(normalizedServerName))
                }
                socket.sslParameters = params
                socket.startHandshake()
                val cert = socket.session.peerCertificates.firstOrNull() as? java.security.cert.X509Certificate
                    ?: error("گواهی X.509 از peer دریافت نشد.")
                val fingerprint = java.security.MessageDigest.getInstance("SHA-256").digest(cert.encoded)
                    .joinToString("") { "%02x".format(it) }
                return Result.success(TlsCertificateAssessment(
                    "${address.hostAddress.substringBefore('%')} (${peerIdentity})", port, cert.subjectX500Principal.name,
                    cert.issuerX500Principal.name, cert.notBefore.time, cert.notAfter.time, fingerprint,
                    socket.session.protocol, socket.session.cipherSuite, auth.authorizationId
                ))
            }
        } catch (e: Exception) {
            runCatching { started.close() }
            return Result.failure(IllegalStateException("TLS handshake یا اعتبارسنجی گواهی ناموفق بود؛ گواهی غیرمعتبر پذیرفته/نادیده گرفته نشد.", e))
        }
    }
}

class AuthorizedTcpConnectProbe {
    fun probe(addressText: String, port: Int, manifest: NetworkScopeManifest?, timeoutMs: Int = 1200, now: Long = System.currentTimeMillis()): TcpProbeResult {
        fun blocked(reason: String) = TcpProbeResult(addressText, port, TcpProbeState.BLOCKED, 0, reason, manifest?.authorizationId.orEmpty())
        if (manifest == null || manifest.authorizationId.isBlank()) return blocked("مجوز شبکه وجود ندارد.")
        if (now > manifest.validUntilEpochMs || manifest.maxProbes !in 1..32) return blocked("مجوز منقضی یا بودجه اسکن نامعتبر است.")
        if (port !in manifest.allowedPorts || port !in 1..65535) return blocked("پورت در allowlist دقیق مجاز نشده است.")
        if (timeoutMs !in 200..1500) return blocked("timeout خارج از محدوده ایمن است.")
        val (address, failure) = NetworkTargetPolicy.validate(addressText, port, manifest, now)
        if (failure != null || address == null) return blocked(failure ?: "هدف مجاز نیست.")
        if (!NetworkProbeBudget.consume(manifest, now)) return blocked("بودجه تعداد probe تکمیل شده است.")
        val canonical = address.hostAddress.substringBefore('%')
        val start = System.nanoTime()
        return try {
            Socket().use { socket -> socket.connect(InetSocketAddress(address, port), timeoutMs) }
            TcpProbeResult(canonical, port, TcpProbeState.OPEN, (System.nanoTime() - start) / 1_000_000L, "اتصال TCP برقرار شد؛ سرویس/نسخه با handshake شناسایی نشده است.", manifest.authorizationId, CommonTcpServiceHints.hint(port))
        } catch (ignored: ConnectException) {
            TcpProbeResult(canonical, port, TcpProbeState.CLOSED, (System.nanoTime() - start) / 1_000_000L, "اتصال رد شد.", manifest.authorizationId, CommonTcpServiceHints.hint(port))
        } catch (ignored: java.net.SocketTimeoutException) {
            TcpProbeResult(canonical, port, TcpProbeState.FILTERED_OR_TIMEOUT, (System.nanoTime() - start) / 1_000_000L, "timeout؛ بسته بودن یا فیلتر بودن از هم قابل تشخیص نیست.", manifest.authorizationId, CommonTcpServiceHints.hint(port))
        } catch (ignored: Exception) {
            TcpProbeResult(canonical, port, TcpProbeState.FILTERED_OR_TIMEOUT, (System.nanoTime() - start) / 1_000_000L, "اتصال برقرار نشد؛ جزئیات شبکه در گزارش عمومی افشا نشد.", manifest.authorizationId, CommonTcpServiceHints.hint(port))
        }
    }

}

