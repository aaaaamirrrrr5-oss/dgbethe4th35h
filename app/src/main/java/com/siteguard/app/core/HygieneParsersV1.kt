package com.siteguard.app.core

import java.time.OffsetDateTime

/** Parsed view of /.well-known/security.txt (RFC 9116). Only fields relevant to a report are retained. */
data class SecurityTxtInfoV1(
    val contacts: List<String>,
    val expiresRaw: String?,
    val expiresEpochMs: Long?,
    val canonical: List<String>,
    val hasPolicy: Boolean,
    val hasEncryption: Boolean,
    val signed: Boolean
) {
    val validContacts: List<String> get() = contacts.filter { c -> listOf("mailto:", "https://", "tel:").any { c.startsWith(it, ignoreCase = true) } }
}

object SecurityTxtV1 {
    fun parse(text: String): SecurityTxtInfoV1 {
        val contacts = mutableListOf<String>()
        val canonical = mutableListOf<String>()
        var expires: String? = null
        var policy = false
        var encryption = false
        var signed = false
        text.lineSequence().take(200).forEach { raw ->
            val line = raw.trim()
            if (line.startsWith("-----BEGIN PGP SIGNED MESSAGE")) signed = true
            if (line.isEmpty() || line.startsWith("#")) return@forEach
            val colon = line.indexOf(':')
            if (colon <= 0) return@forEach
            val key = line.substring(0, colon).trim().lowercase()
            val value = line.substring(colon + 1).trim()
            when (key) {
                "contact" -> if (value.isNotEmpty() && contacts.size < 10) contacts += value.take(200)
                "expires" -> if (expires == null) expires = value.take(64)
                "canonical" -> if (value.isNotEmpty() && canonical.size < 5) canonical += value.take(200)
                "policy" -> policy = true
                "encryption" -> encryption = true
            }
        }
        return SecurityTxtInfoV1(contacts, expires, expires?.let(::parseInstantMs), canonical, policy, encryption, signed)
    }

    internal fun parseInstantMs(value: String): Long? =
        runCatching { OffsetDateTime.parse(value.trim()).toInstant().toEpochMilli() }.getOrNull()

    /** [status] is the HTTP status of the request; [info] is non-null only when a 200 body was parsed. */
    fun evaluate(host: String, status: Int, info: SecurityTxtInfoV1?, nowMs: Long = System.currentTimeMillis()): List<Finding> {
        val asset = "$host:443"
        fun f(id: String, title: String, severity: Severity, st: FindingStatus, description: String, fix: String, evidence: String) = Finding(
            id = id, title = title, severity = severity, description = description, remediation = fix, confidence = "Medium",
            evidence = evidence, cwe = "CWE-1059", status = st, affectedAsset = asset, exactLocation = "/.well-known/security.txt",
            detectionMethod = "Single pinned HTTPS GET, redirect not followed, RFC 9116 field parsing",
            notTested = "درستی امضای PGP، دسترس‌پذیری آدرس‌های Contact/Policy و مسیر قدیمی /security.txt بررسی نشد.",
            residualRisk = "نبود یا ایراد این فایل آسیب‌پذیری نیست؛ فقط مسیر گزارش مسئولانه را برای پژوهشگران مبهم می‌کند."
        )
        if (info == null) {
            return if (status == 404 || status == 410) listOf(
                f("SG-SECTXT-MISSING", "فایل security.txt پیدا نشد", Severity.INFO, FindingStatus.INFORMATIONAL,
                    "RFC 9116 انتشار /.well-known/security.txt را برای اعلام مسیر گزارش آسیب‌پذیری توصیه می‌کند.",
                    "فایلی با فیلدهای Contact و Expires در /.well-known/security.txt منتشر کنید.", "GET /.well-known/security.txt -> HTTP $status")
            ) else emptyList()
        }
        val out = mutableListOf<Finding>()
        if (info.validContacts.isEmpty()) {
            out += f("SG-SECTXT-NO-CONTACT", "security.txt فیلد Contact معتبر ندارد", Severity.LOW, FindingStatus.PROBABLE,
                "فیلد Contact الزامی است و باید با mailto:، https:// یا tel: شروع شود.",
                "حداقل یک Contact معتبر اضافه کنید.", "contacts=${info.contacts.size}; valid=0")
        }
        if (info.expiresRaw == null) {
            out += f("SG-SECTXT-NO-EXPIRES", "security.txt فیلد Expires ندارد", Severity.LOW, FindingStatus.PROBABLE,
                "فیلد Expires الزامی است تا اطلاعات منقضی‌شده قابل تشخیص باشد.",
                "تاریخ انقضای حداکثر یک‌ساله با قالب ISO 8601 اضافه کنید.", "Expires: missing")
        } else if (info.expiresEpochMs == null) {
            out += f("SG-SECTXT-BAD-EXPIRES", "مقدار Expires در security.txt قابل پارس نیست", Severity.LOW, FindingStatus.PROBABLE,
                "مقدار Expires باید تاریخ-زمان ISO 8601 باشد.", "قالب را اصلاح کنید؛ مثلاً 2027-12-31T23:59:59Z.", "Expires: ${EvidenceSanitizer.sanitize(info.expiresRaw).take(64)}")
        } else if (info.expiresEpochMs < nowMs) {
            out += f("SG-SECTXT-EXPIRED", "security.txt منقضی شده است", Severity.LOW, FindingStatus.PROBABLE,
                "تاریخ Expires گذشته است؛ پژوهشگران نباید به Contact آن اعتماد کنند.",
                "فایل را بازبینی و Expires را تمدید کنید.", "Expires: ${EvidenceSanitizer.sanitize(info.expiresRaw).take(64)}")
        }
        return out
    }
}

data class HstsInfoV1(val raw: String, val maxAgeSeconds: Long?, val includeSubDomains: Boolean, val preload: Boolean)

object HstsPolicyV1 {
    private const val SIX_MONTHS = 15_552_000L
    private const val ONE_YEAR = 31_536_000L

    fun parse(value: String): HstsInfoV1 {
        var maxAge: Long? = null
        var include = false
        var preload = false
        value.split(';').map { it.trim() }.filter { it.isNotEmpty() }.forEach { directive ->
            val lower = directive.lowercase()
            when {
                lower.startsWith("max-age") -> {
                    val v = directive.substringAfter('=', "").trim().trim('"')
                    if (maxAge == null) maxAge = v.toLongOrNull()?.takeIf { it >= 0 }
                }
                lower == "includesubdomains" -> include = true
                lower == "preload" -> preload = true
            }
        }
        return HstsInfoV1(value.take(200), maxAge, include, preload)
    }

    /** A missing HSTS header is already reported by the main scan (SG-TLS-001); this evaluates a header that IS present. */
    fun evaluate(host: String, info: HstsInfoV1): List<Finding> {
        val out = mutableListOf<Finding>()
        fun f(id: String, title: String, severity: Severity, description: String, fix: String) {
            out += Finding(
                id = id, title = title, severity = severity, description = description, remediation = fix, confidence = "Medium",
                evidence = "Strict-Transport-Security: ${EvidenceSanitizer.sanitize(info.raw).take(160)}", cwe = "CWE-319",
                status = FindingStatus.PROBABLE, affectedAsset = "$host:443", exactLocation = "HTTPS response header",
                detectionMethod = "Header read from one HTTPS response and parsed",
                notTested = "هدر در پاسخ زیر دامنه‌ها و مسیرهای دیگر و وضعیت preload list رسمی بررسی نشد.",
                residualRisk = "فقط یک پاسخ دیده شد؛ پاسخ‌های دیگر ممکن است هدر متفاوتی داشته باشند."
            )
        }
        val maxAge = info.maxAgeSeconds
        when {
            maxAge == null -> f("SG-HSTS-INVALID", "هدر HSTS بدون max-age معتبر است", Severity.LOW,
                "بدون max-age عددی مرورگرها هدر را نادیده می‌گیرند.", "مقدار max-age را عددی و حداقل ۶ ماه (15552000) تنظیم کنید.")
            maxAge == 0L -> f("SG-HSTS-DISABLED", "HSTS با max-age=0 غیرفعال شده است", Severity.MEDIUM,
                "max-age=0 سیاست HSTS ذخیره‌شده در مرورگر را حذف می‌کند.", "پس از اطمینان از پشتیبانی کامل HTTPS مقدار مناسب (حداقل ۶ ماه) را تنظیم کنید.")
            (maxAge ?: 0L) < SIX_MONTHS -> f("SG-HSTS-SHORT", "max-age در HSTS کوتاه است", Severity.LOW,
                "max-age=$maxAge ثانیه از ۶ ماه کمتر است و پنجرهٔ محافظت کوتاه می‌ماند.", "به‌تدریج max-age را تا حداقل 15552000 (و برای preload 31536000) افزایش دهید.")
        }
        if (info.preload && ((maxAge ?: 0L) < ONE_YEAR || !info.includeSubDomains)) {
            f("SG-HSTS-PRELOAD-INELIGIBLE", "پرچم preload بدون شرایط لازم تنظیم شده است", Severity.LOW,
                "برای preload لازم است max-age حداقل یک سال و includeSubDomains فعال باشد.",
                "قبل از ثبت در preload list، max-age و includeSubDomains را اصلاح کنید؛ حذف از preload list کند و دشوار است.")
        }
        return out
    }
}
