package com.siteguard.app.core

import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.cert.X509Certificate
import javax.net.ssl.SSLSession

/** What this device observed after a SUCCESSFUL TLS handshake with one endpoint (one negotiated session, leaf certificate). */
data class TlsSessionInfoV1(
    val protocol: String,
    val cipherSuite: String,
    val subject: String,
    val issuer: String,
    val notBeforeEpochMs: Long,
    val notAfterEpochMs: Long,
    val signatureAlgorithm: String,
    val keyAlgorithm: String,
    val keyBits: Int,
    val sanDnsCount: Int,
    val chainLength: Int
) {
    companion object {
        /** Returns null if the session carries no X.509 peer certificate or anything fails to parse. */
        fun fromSession(session: SSLSession): TlsSessionInfoV1? = runCatching {
            val chain = session.peerCertificates
            val leaf = chain.firstOrNull() as? X509Certificate ?: return@runCatching null
            val key = leaf.publicKey
            val bits = when (key) {
                is RSAPublicKey -> key.modulus.bitLength()
                is ECPublicKey -> key.params.order.bitLength()
                else -> 0
            }
            TlsSessionInfoV1(
                protocol = session.protocol.orEmpty(),
                cipherSuite = session.cipherSuite.orEmpty(),
                subject = leaf.subjectX500Principal.name.take(300),
                issuer = leaf.issuerX500Principal.name.take(300),
                notBeforeEpochMs = leaf.notBefore.time,
                notAfterEpochMs = leaf.notAfter.time,
                signatureAlgorithm = leaf.sigAlgName.orEmpty(),
                keyAlgorithm = key.algorithm.orEmpty(),
                keyBits = bits,
                sanDnsCount = leaf.subjectAlternativeNames?.count { (it.firstOrNull() as? Int) == 2 } ?: 0,
                chainLength = chain.size
            )
        }.getOrNull()
    }
}

/**
 * Turns one observed TLS session into findings. Everything here comes from a single handshake on this device:
 * it cannot enumerate other protocol versions or cipher suites the server may also accept, and it does not inspect
 * intermediates, OCSP or Certificate Transparency. Findings are therefore PROBABLE/INFORMATIONAL, never CONFIRMED.
 */
object TlsSessionEvaluatorV1 {
    private const val DAY_MS = 86_400_000L
    private val LEGACY_PROTOCOLS = setOf("SSLv3", "TLSv1", "TLSv1.1")
    private val WEAK_CIPHER_MARKERS = listOf("RC4", "3DES", "_NULL_", "EXPORT", "_anon_", "DES_CBC")

    private fun day(epochMs: Long): String = java.time.Instant.ofEpochMilli(epochMs).toString().take(10)

    fun evaluate(host: String, info: TlsSessionInfoV1, nowMs: Long = System.currentTimeMillis()): List<Finding> {
        val out = mutableListOf<Finding>()
        val subject = EvidenceSanitizer.sanitize(info.subject).take(160)
        val issuer = EvidenceSanitizer.sanitize(info.issuer).take(160)
        val daysLeft = (info.notAfterEpochMs - nowMs) / DAY_MS
        val asset = "$host:443"
        val location = "TLS session and leaf certificate"
        val method = "One successful handshake; negotiated parameters and leaf certificate read from the session"
        val notTested = "نسخه‌ها و cipherهای دیگری که سرور ممکن است بپذیرد، زنجیرهٔ میانی، OCSP و Certificate Transparency بررسی نشد."

        fun add(id: String, title: String, severity: Severity, status: FindingStatus, description: String, fix: String, evidence: String, cwe: String) {
            out += Finding(
                id = id, title = title, severity = severity, description = description, remediation = fix, confidence = "Medium",
                evidence = evidence, cwe = cwe, status = status, affectedAsset = asset, exactLocation = location,
                detectionMethod = method, notTested = notTested,
                residualRisk = "فقط یک نشست TLS از همین دستگاه دیده شد؛ ساعت دستگاه، پروکسی یا VPN می‌تواند مقادیر را تغییر دهد."
            )
        }

        if (info.protocol in LEGACY_PROTOCOLS) {
            add("SG-TLS-LEGACY-PROTOCOL", "سرور پروتکل قدیمی ${info.protocol} را مذاکره کرد", Severity.MEDIUM, FindingStatus.PROBABLE,
                "نشست TLS با پروتکل منسوخ ${info.protocol} برقرار شد.",
                "TLS 1.2 و TLS 1.3 را فعال و نسخه‌های ۱.۱ و پایین‌تر را غیرفعال کنید.",
                "protocol=${info.protocol}; cipher=${info.cipherSuite}", "CWE-327")
        }
        if (WEAK_CIPHER_MARKERS.any { info.cipherSuite.contains(it, ignoreCase = true) }) {
            add("SG-TLS-WEAK-CIPHER", "cipher suite ضعیف مذاکره شد", Severity.MEDIUM, FindingStatus.PROBABLE,
                "cipher suite مذاکره‌شده شامل الگوریتم منسوخ یا بدون رمزنگاری قوی است.",
                "فقط cipherهای AEAD با forward secrecy (ECDHE + AES-GCM/ChaCha20) را فعال کنید.",
                "cipher=${info.cipherSuite}", "CWE-327")
        }
        val weakKey = (info.keyAlgorithm.equals("RSA", true) && info.keyBits in 1..2047) ||
            (info.keyAlgorithm.equals("EC", true) && info.keyBits in 1..223)
        if (weakKey) {
            add("SG-TLS-WEAK-KEY", "کلید عمومی گواهی کوتاه است", Severity.MEDIUM, FindingStatus.PROBABLE,
                "گواهی برگ از کلید ${info.keyAlgorithm} با ${info.keyBits} بیت استفاده می‌کند.",
                "گواهی جدید با RSA حداقل ۲۰۴۸ بیت یا ECDSA حداقل P-256 صادر کنید.",
                "key=${info.keyAlgorithm}/${info.keyBits}; subject=$subject", "CWE-326")
        }
        val sigUpper = info.signatureAlgorithm.uppercase()
        if (sigUpper.contains("MD5") || sigUpper.contains("SHA1")) {
            add("SG-TLS-WEAK-SIGNATURE", "گواهی برگ با الگوریتم امضای ضعیف امضا شده است", Severity.MEDIUM, FindingStatus.PROBABLE,
                "الگوریتم امضای گواهی برگ ${info.signatureAlgorithm} است.",
                "گواهی را با SHA-256 یا قوی‌تر مجدداً صادر کنید.",
                "signature=${info.signatureAlgorithm}; issuer=$issuer", "CWE-328")
        }
        if (daysLeft in 0..30) {
            add("SG-TLS-CERT-EXPIRING", "گواهی TLS ظرف ${daysLeft} روز منقضی می‌شود",
                if (daysLeft <= 14) Severity.MEDIUM else Severity.LOW, FindingStatus.PROBABLE,
                "تاریخ پایان گواهی برگ نزدیک است؛ انقضا باعث خطای مرورگر و قطع سرویس می‌شود.",
                "تمدید خودکار (مثلاً ACME) را فعال کنید و هشدار انقضا تنظیم کنید.",
                "notAfter=${day(info.notAfterEpochMs)}; daysLeft=$daysLeft; issuer=$issuer", "CWE-298")
        }
        add("SG-TLS-OBSERVED", "جزئیات نشست TLS مشاهده‌شده", Severity.INFO, FindingStatus.INFORMATIONAL,
            "خلاصهٔ پارامترهای مذاکره‌شده و گواهی برگ در یک handshake موفق؛ برای ثبت در گزارش و مقایسهٔ آینده.",
            "اقدامی لازم نیست؛ اگر مقادیر غیرمنتظره‌اند با مدیر سرور بررسی کنید.",
            "protocol=${info.protocol}; cipher=${info.cipherSuite}; key=${info.keyAlgorithm}/${info.keyBits}; sig=${info.signatureAlgorithm}; " +
                "validity=${day(info.notBeforeEpochMs)}..${day(info.notAfterEpochMs)}; SAN-DNS=${info.sanDnsCount}; chain=${info.chainLength}; issuer=$issuer",
            "CWE-295")
        return out
    }
}
