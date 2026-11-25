package com.siteguard.app.core

import java.io.EOFException
import java.net.SocketException
import java.net.SocketTimeoutException
import java.security.cert.CertPathBuilderException
import java.security.cert.CertPathValidatorException
import java.security.cert.CertificateException
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateNotYetValidException
import java.security.cert.CertificateRevokedException
import java.util.Locale
import javax.net.ssl.SSLException
import javax.net.ssl.SSLPeerUnverifiedException

/** Why a TLS handshake did not complete, as observed from this device's platform trust store. */
enum class TlsFailureKind(val findingId: String) {
    CERTIFICATE_EXPIRED("SG-TLS-VALIDATION-EXPIRED"),
    CERTIFICATE_NOT_YET_VALID("SG-TLS-VALIDATION-NOT-YET-VALID"),
    CERTIFICATE_REVOKED("SG-TLS-VALIDATION-REVOKED"),
    WEAK_ALGORITHM("SG-TLS-VALIDATION-WEAK-ALGORITHM"),
    HOSTNAME_MISMATCH("SG-TLS-VALIDATION-HOSTNAME"),
    UNTRUSTED_CHAIN("SG-TLS-VALIDATION-UNTRUSTED-CHAIN"),
    NON_TLS_ENDPOINT("SG-TLS-VALIDATION-NON-TLS-ENDPOINT"),
    HANDSHAKE_REJECTED("SG-TLS-VALIDATION-HANDSHAKE-REJECTED")
}

data class TlsFailure(
    val kind: TlsFailureKind,
    /** Exception class names from outermost to innermost, e.g. "SSLHandshakeException > CertPathValidatorException". */
    val exceptionChain: String,
    /** Sanitized, single-line, length-limited message of the most informative exception. */
    val detail: String
)

/**
 * Classifies exceptions thrown while establishing a TLS connection. A certificate or handshake failure is the most
 * important TLS observation, so it must become a finding instead of an anonymous "connection failed" message.
 *
 * It deliberately returns null for ordinary network problems (timeouts, resets, refused connections): those say nothing
 * about the server's TLS configuration and must not be reported as TLS findings.
 */
object TlsFailureClassifier {
    private const val MAX_CHAIN_DEPTH = 8

    fun classify(error: Throwable): TlsFailure? {
        val chain = causeChain(error)
        val tlsRelated = chain.any {
            it is SSLException || it is CertificateException || it is CertPathValidatorException || it is CertPathBuilderException
        }
        if (!tlsRelated) return null

        val messages = chain.mapNotNull { it.message }.map { normalize(it) }
        fun anyMessage(vararg needles: String) = messages.any { message -> needles.any { message.contains(it) } }
        val reasons = chain.filterIsInstance<CertPathValidatorException>().map { it.reason }

        val kind: TlsFailureKind? = when {
            chain.any { it is CertificateExpiredException } ||
                reasons.any { it == CertPathValidatorException.BasicReason.EXPIRED } ||
                anyMessage("certificate expired", "certificateexpired", "notafter") -> TlsFailureKind.CERTIFICATE_EXPIRED

            chain.any { it is CertificateNotYetValidException } ||
                reasons.any { it == CertPathValidatorException.BasicReason.NOT_YET_VALID } ||
                anyMessage("not yet valid", "notbefore") -> TlsFailureKind.CERTIFICATE_NOT_YET_VALID

            chain.any { it is CertificateRevokedException } ||
                reasons.any { it == CertPathValidatorException.BasicReason.REVOKED } ||
                anyMessage("certificate revoked") -> TlsFailureKind.CERTIFICATE_REVOKED

            reasons.any { it == CertPathValidatorException.BasicReason.ALGORITHM_CONSTRAINED } ||
                anyMessage("algorithm constraints", "disabled algorithm") -> TlsFailureKind.WEAK_ALGORITHM

            chain.any { it is SSLPeerUnverifiedException } ||
                anyMessage("hostname", "subject alternative", "no name matching", "not verified") -> TlsFailureKind.HOSTNAME_MISMATCH

            chain.any { it is CertPathValidatorException || it is CertPathBuilderException } ||
                anyMessage("trust anchor", "valid certification path", "chain validation failed", "self signed", "self-signed",
                    "unknown ca", "certificate unknown") -> TlsFailureKind.UNTRUSTED_CHAIN

            anyMessage("wrong version number", "first record does not look like a tls", "unrecognized ssl message",
                "packet does not look like") -> TlsFailureKind.NON_TLS_ENDPOINT

            anyMessage("protocol version", "handshake failure", "no cipher suites in common", "no appropriate protocol",
                "unsupported protocol", "inappropriate fallback") -> TlsFailureKind.HANDSHAKE_REJECTED

            // Plain connectivity problems wrapped inside an SSLException say nothing about the server's TLS setup.
            chain.any { it is SocketTimeoutException || it is SocketException || it is EOFException } ||
                anyMessage("connection closed", "connection reset", "closed by peer", "unexpected end of stream",
                    "read timed out", "broken pipe") -> null

            chain.any { it is SSLException } -> TlsFailureKind.HANDSHAKE_REJECTED
            else -> null
        }
        kind ?: return null

        return TlsFailure(
            kind = kind,
            exceptionChain = chain.joinToString(" > ") { it.javaClass.simpleName.ifBlank { it.javaClass.name } },
            detail = describe(chain)
        )
    }

    fun toFinding(host: String, port: Int, failure: TlsFailure): Finding {
        val spec = specFor(failure.kind)
        val evidence = "TLS handshake to $host:$port failed during certificate/handshake validation. " +
            "Exceptions: ${failure.exceptionChain}. Detail: ${failure.detail}"
        return Finding(
            id = failure.kind.findingId,
            title = spec.title,
            severity = spec.severity,
            description = spec.description + CLIENT_SIDE_CAVEAT,
            remediation = spec.remediation,
            confidence = if (spec.status == FindingStatus.PROBABLE) "Medium" else "Low",
            evidence = evidence,
            cwe = spec.cwe,
            status = spec.status,
            affectedAsset = "$host:$port",
            exactLocation = "TLS handshake / server certificate",
            detectionMethod = "Pinned-IP TLS handshake with platform trust store and HTTPS hostname verification",
            businessImpact = spec.impact,
            exploitPrerequisites = "برای کاربران، مرورگرها یا کلاینت‌هایی که همین اعتبارسنجی را انجام می‌دهند، اتصال امن برقرار نمی‌شود یا هشدار نمایش داده می‌شود.",
            safeValidation = "از شبکه یا دستگاه دیگری، گواهی و زنجیره را با openssl s_client یا یک ابزار عمومی بررسی TLS مقایسه کنید؛ ساعت دستگاه و وجود proxy/VPN را هم بررسی کنید.",
            notTested = "هدرهای HTTP، کوکی‌ها و محتوا بررسی نشدند چون هیچ پاسخ HTTP دریافت نشد؛ نسخه‌های پروتکل و cipherهای پشتیبانی‌شده سرور فهرست نشدند.",
            verificationProcedure = "پس از اصلاح، همان اتصال TLS را دوباره اجرا کنید و تکمیل دست‌دهی بدون خطای اعتبارسنجی را تأیید کنید.",
            expectedResult = "دست‌دهی TLS کامل شود و اعتبارسنجی گواهی/نام میزبان بدون استثنا انجام شود.",
            actualResult = "دست‌دهی با خطا متوقف شد: ${failure.kind.name}.",
            residualRisk = "علت دقیق (مشکل سرور، ساعت دستگاه، رهگیری شبکه یا CA سفارشی) از روی یک اتصال قابل اثبات نیست."
        )
    }

    private const val CLIENT_SIDE_CAVEAT =
        " این مشاهده از دید همین دستگاه و trust store آن است؛ ساعت نادرست دستگاه، proxy/VPN یا CA سفارشی هم می‌تواند علت باشد، پس پیش از نتیجه‌گیری باید از شبکه دیگر تأیید شود."

    private data class Spec(
        val title: String,
        val severity: Severity,
        val status: FindingStatus,
        val cwe: String,
        val description: String,
        val remediation: String,
        val impact: String
    )

    private fun specFor(kind: TlsFailureKind): Spec = when (kind) {
        TlsFailureKind.CERTIFICATE_EXPIRED -> Spec(
            "گواهی TLS منقضی‌شده به نظر می‌رسد", Severity.HIGH, FindingStatus.PROBABLE, "CWE-298",
            "اعتبارسنجی گواهی به‌دلیل انقضا (یا خطای تاریخ اعتبار) متوقف شد.",
            "گواهی را تمدید کنید، زنجیره‌ی کامل را نصب کنید و تمدید خودکار را با پایش انقضا فعال کنید.",
            "کاربران هشدار امنیتی می‌بینند یا اتصال قطع می‌شود؛ کلاینت‌هایی که هشدار را نادیده می‌گیرند در معرض رهگیری قرار می‌گیرند."
        )
        TlsFailureKind.CERTIFICATE_NOT_YET_VALID -> Spec(
            "گواهی TLS هنوز معتبر نیست", Severity.MEDIUM, FindingStatus.PROBABLE, "CWE-295",
            "تاریخ شروع اعتبار گواهی از زمان فعلی دستگاه دیرتر است؛ ساعت نادرست دستگاه محتمل‌ترین علت جایگزین است.",
            "ساعت دستگاه را بررسی کنید و اگر سرور هم گواهی با تاریخ آینده دارد، گواهی را با تاریخ درست صادر کنید.",
            "اتصال امن برقرار نمی‌شود تا زمانی که تاریخ اعتبار و ساعت کلاینت هماهنگ شوند."
        )
        TlsFailureKind.CERTIFICATE_REVOKED -> Spec(
            "گواهی TLS ابطال‌شده به نظر می‌رسد", Severity.HIGH, FindingStatus.PROBABLE, "CWE-299",
            "اعتبارسنجی گزارش داد گواهی ابطال شده است.",
            "گواهی جدید صادر و نصب کنید، کلید خصوصی قبلی را تعویض کنید و علت ابطال را بررسی کنید.",
            "گواهی ابطال‌شده نشانه‌ی احتمالی افشای کلید یا اشتباه صدور است و کلاینت‌ها آن را رد می‌کنند."
        )
        TlsFailureKind.WEAK_ALGORITHM -> Spec(
            "گواهی با الگوریتم نامجاز یا ضعیف", Severity.MEDIUM, FindingStatus.PROBABLE, "CWE-327",
            "زنجیره‌ی گواهی با محدودیت‌های الگوریتم پلتفرم (مثلاً امضای ضعیف) سازگار نبود.",
            "گواهی و زنجیره را با الگوریتم‌های امضای مدرن (RSA ≥ 2048 یا ECDSA با SHA-256 به بالا) دوباره صادر کنید.",
            "کلاینت‌های جدید گواهی را رد می‌کنند و امنیت امضا ضعیف است."
        )
        TlsFailureKind.HOSTNAME_MISMATCH -> Spec(
            "نام میزبان با گواهی TLS مطابقت ندارد", Severity.HIGH, FindingStatus.PROBABLE, "CWE-297",
            "نام میزبان هدف در CN/SAN گواهی ارائه‌شده پیدا نشد.",
            "گواهی را برای نام دقیق میزبان (SAN) صادر کنید یا گواهی/virtual host درست را روی این نام و درگاه فعال کنید.",
            "کاربران هشدار عدم تطابق می‌بینند و تمایز سرور واقعی از سرور جعلی دشوار می‌شود."
        )
        TlsFailureKind.UNTRUSTED_CHAIN -> Spec(
            "زنجیره‌ی گواهی TLS قابل اعتماد نیست", Severity.HIGH, FindingStatus.PROBABLE, "CWE-295",
            "زنجیره‌ی گواهی به یک CA مورد اعتماد پلتفرم نرسید (خودامضا، CA ناشناس یا زنجیره‌ی ناقص).",
            "گواهی از CA عمومی معتبر دریافت کنید و گواهی‌های میانی (intermediate) را کامل روی سرور نصب کنید.",
            "مرورگرها و برنامه‌ها هشدار می‌دهند یا اتصال را رد می‌کنند؛ عادت به نادیده‌گرفتن هشدار خطر رهگیری را بالا می‌برد."
        )
        TlsFailureKind.NON_TLS_ENDPOINT -> Spec(
            "درگاه HTTPS پروتکل TLS صحبت نمی‌کند", Severity.MEDIUM, FindingStatus.UNVERIFIED, "",
            "پاسخ سرور شبیه یک دست‌دهی TLS نبود؛ احتمالاً روی این درگاه سرویس غیر TLS (مثلاً HTTP ساده) فعال است.",
            "درگاه را به TLS واقعی متصل کنید یا نشانی را به درگاه/پروتکل درست اصلاح کنید.",
            "اگر سرویس باید HTTPS باشد، ترافیک بدون محافظت TLS ارسال می‌شود."
        )
        TlsFailureKind.HANDSHAKE_REJECTED -> Spec(
            "دست‌دهی TLS توسط سرور یا کلاینت رد شد", Severity.MEDIUM, FindingStatus.UNVERIFIED, "",
            "دست‌دهی TLS تکمیل نشد (عدم توافق روی نسخه‌ی پروتکل یا cipher، یا خطای دیگر لایه‌ی TLS).",
            "پیکربندی TLS را بررسی کنید: TLS 1.2/1.3 فعال، cipherهای مدرن، SNI و گواهی درست روی همین نام و درگاه.",
            "کلاینت‌های سازگار ممکن است نتوانند وصل شوند یا سرور از پروتکل‌های ناامن استفاده کند."
        )
    }

    private fun causeChain(error: Throwable): List<Throwable> {
        val seen = java.util.IdentityHashMap<Throwable, Boolean>()
        val out = mutableListOf<Throwable>()
        var current: Throwable? = error
        while (current != null && out.size < MAX_CHAIN_DEPTH && seen.put(current, true) == null) {
            out += current
            current = current.cause
        }
        return out
    }

    private fun normalize(message: String): String =
        message.lowercase(Locale.ROOT).replace('_', ' ').replace(Regex("\\s+"), " ").trim()

    private fun describe(chain: List<Throwable>): String {
        val raw = chain.mapNotNull { it.message?.takeIf(String::isNotBlank) }.firstOrNull().orEmpty()
        val oneLine = raw.replace(Regex("\\s+"), " ").trim().take(200)
        return EvidenceSanitizer.sanitize(oneLine).ifBlank { "no message" }
    }
}
