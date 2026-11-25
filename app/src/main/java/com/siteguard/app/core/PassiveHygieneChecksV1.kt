package com.siteguard.app.core

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.net.URI

/** Parsed, bounded view of robots.txt. robots.txt is a crawler convention, not access control. */
data class RobotsInfoV1(
    val disallowPaths: List<String>,
    val sitemapUrls: List<String>,
    val externalSitemapCount: Int,
    val crawlDelaySeconds: Int?,
    val sensitivePathHints: List<String>
)

object RobotsTxtV1 {
    private val SENSITIVE_WORDS = listOf(
        "admin", "backup", "bak", ".git", ".env", "private", "internal", "staging", "config", "dump", "phpmyadmin", "secret", "debug", "old", "db"
    )

    fun parse(text: String, host: String): RobotsInfoV1 {
        val disallow = linkedSetOf<String>()
        val sitemaps = linkedSetOf<String>()
        var external = 0
        var crawlDelay: Int? = null
        val canonical = canonicalHost(host)
        text.lineSequence().take(1_000).forEach { rawLine ->
            val line = rawLine.substringBefore('#').trim()
            val colon = line.indexOf(':')
            if (colon <= 0) return@forEach
            val key = line.substring(0, colon).trim().lowercase()
            val value = line.substring(colon + 1).trim()
            when (key) {
                "disallow" -> if (value.startsWith("/") && value.length <= 200 && disallow.size < 200) disallow += value
                "crawl-delay" -> value.toIntOrNull()?.takeIf { it in 0..3_600 }?.let { crawlDelay = crawlDelay ?: it }
                "sitemap" -> {
                    val uri = runCatching { URI(value) }.getOrNull()
                    val sameHost = uri != null && uri.scheme?.lowercase() in setOf("http", "https") && uri.rawUserInfo == null &&
                        uri.host?.let { canonicalHost(it) } == canonical
                    if (sameHost && sitemaps.size < 10) sitemaps += value.take(300) else external++
                }
            }
        }
        val hints = disallow.filter { path ->
            val lower = path.lowercase()
            SENSITIVE_WORDS.any { word -> lower.split('/', '.', '-', '_').any { it == word.trim('.') } || (word.startsWith('.') && lower.contains(word)) }
        }.take(20)
        return RobotsInfoV1(disallow.toList(), sitemaps.toList(), external, crawlDelay, hints)
    }
}

object SitemapV1 {
    /** Regex-based on purpose: no XML parser means no DTD/entity expansion surface for untrusted input. */
    private val LOC = Regex("(?is)<loc>\\s*([^<\\s]{1,500})\\s*</loc>")

    fun isIndex(xml: String): Boolean = Regex("(?i)<sitemapindex\\b").containsMatchIn(xml.take(4_096))

    /** Same-host http(s) URLs without query/user-info, capped. Entities such as &amp; mean the URL carries a query and is dropped. */
    fun sameHostLocs(xml: String, host: String, limit: Int = 200): List<String> {
        val canonical = canonicalHost(host)
        val out = linkedSetOf<String>()
        for (m in LOC.findAll(xml.take(256 * 1024))) {
            if (out.size >= limit) break
            val value = m.groupValues[1]
            val uri = runCatching { URI(value) }.getOrNull() ?: continue
            if (uri.scheme?.lowercase() !in setOf("http", "https") || uri.rawUserInfo != null || uri.rawQuery != null || uri.rawFragment != null) continue
            if (uri.host?.let { canonicalHost(it) } != canonical) continue
            out += value
        }
        return out.toList()
    }
}

enum class HttpsRedirectResultV1 { PERMANENT_TO_HTTPS, TEMPORARY_TO_HTTPS, REDIRECT_TO_OTHER_TARGET, SERVES_OVER_HTTP, OTHER_STATUS }

object HttpsRedirectEvaluatorV1 {
    fun evaluate(host: String, status: Int, location: String?): HttpsRedirectResultV1 {
        if (status in setOf(301, 302, 303, 307, 308)) {
            val uri = location?.trim()?.takeIf { it.isNotEmpty() }?.let { runCatching { URI(it) }.getOrNull() }
            val toHttpsSameHost = uri != null && uri.scheme.equals("https", true) && uri.host?.let { canonicalHost(it) } == canonicalHost(host)
            return when {
                toHttpsSameHost && status in setOf(301, 308) -> HttpsRedirectResultV1.PERMANENT_TO_HTTPS
                toHttpsSameHost -> HttpsRedirectResultV1.TEMPORARY_TO_HTTPS
                else -> HttpsRedirectResultV1.REDIRECT_TO_OTHER_TARGET
            }
        }
        return if (status in 200..299) HttpsRedirectResultV1.SERVES_OVER_HTTP else HttpsRedirectResultV1.OTHER_STATUS
    }

    /** Returns null when the observation needs no finding. All findings are observations of one response and say so. */
    fun toFinding(host: String, result: HttpsRedirectResultV1, status: Int, location: String?): Finding? {
        val base = { id: String, title: String, severity: Severity, description: String, fix: String, st: FindingStatus, conf: String ->
            Finding(
                id = id, title = title, severity = severity, description = description, remediation = fix, confidence = conf,
                evidence = "GET http://$host/ -> HTTP $status" + (location?.let { "; Location: ${EvidenceSanitizer.sanitize(it).take(200)}" } ?: ""),
                cwe = "CWE-319", status = st, affectedAsset = "$host:80", exactLocation = "HTTP port 80 root response",
                detectionMethod = "Single pinned GET to port 80, redirect not followed",
                notTested = "مسیرهای دیگر، پورت‌های دیگر، HSTS preload و رفتار پس از redirect دنبال‌نشده بررسی نشد.",
                residualRisk = "فقط پاسخ ریشه روی پورت ۸۰ دیده شد؛ سایر مسیرها ممکن است رفتار متفاوتی داشته باشند."
            )
        }
        return when (result) {
            HttpsRedirectResultV1.SERVES_OVER_HTTP -> base(
                "SG-HTTPS-REDIRECT-MISSING", "پورت ۸۰ محتوا را بدون redirect به HTTPS سرو می‌کند", Severity.MEDIUM,
                "ریشهٔ سایت روی HTTP بدون redirect پاسخ ۲xx داد؛ کاربرانی که آدرس را بدون https وارد می‌کنند ممکن است ترافیک رمزنشده بفرستند. ممکن است برای محتوای عمومی عمدی باشد.",
                "روی پورت ۸۰ یک redirect دائمی (301/308) به همان میزبان در HTTPS تنظیم کنید و HSTS را پس از اطمینان فعال کنید.",
                FindingStatus.PROBABLE, "Medium"
            )
            HttpsRedirectResultV1.TEMPORARY_TO_HTTPS -> base(
                "SG-HTTPS-REDIRECT-TEMPORARY", "redirect به HTTPS موقت است", Severity.INFO,
                "پاسخ $status به HTTPS همان میزبان دیده شد؛ redirect موقت توسط مرورگرها کش نمی‌شود و هر بار یک درخواست HTTP اولیه ارسال می‌شود.",
                "در صورت پایدار بودن تنظیم، از 301 یا 308 و سپس HSTS استفاده کنید.",
                FindingStatus.INFORMATIONAL, "High"
            )
            HttpsRedirectResultV1.REDIRECT_TO_OTHER_TARGET -> base(
                "SG-HTTPS-REDIRECT-OTHER", "redirect پورت ۸۰ به مقصد غیر از HTTPS همان میزبان است", Severity.LOW,
                "پاسخ $status به مقصدی غیر از https همان میزبان اشاره می‌کند (دنبال نشد). ممکن است به www، دامنهٔ دیگر یا HTTP اشاره کند.",
                "مقصد redirect را بررسی کنید؛ ایدهٔ ایمن، رسیدن مستقیم به HTTPS همان میزبان است.",
                FindingStatus.UNVERIFIED, "Medium"
            )
            else -> null
        }
    }
}

data class PassiveHygieneReportV1(
    val findings: List<Finding>,
    val events: List<WebsiteDiscoveryEventV1>,
    val robots: RobotsInfoV1?,
    val sitemapUrlCount: Int,
    val requestsUsed: Int,
    val limitations: List<String>,
    val tls: TlsSessionInfoV1? = null,
    val host: String = "",
    val securityTxt: SecurityTxtInfoV1? = null,
    val hsts: HstsInfoV1? = null
)

/** robots.txt, sitemap and HTTP->HTTPS checks. Each request is re-authorized and counted against the manifest budget. */
object PassiveHygieneChecksV1 {
    val LIMITATIONS = listOf(
        "رکوردهای DNS (SPF/DMARC/CAA/MX/NS/TXT) بررسی نشدند: java.net در اندروید API رکورد TXT/CAA ندارد؛ نیازمند DoH یا کتابخانهٔ resolver است.",
        "security.txt فقط وجود و فیلدهای Contact/Expires را بررسی می‌کند؛ امضای PGP و دسترس‌پذیری لینک‌ها آزمایش نمی‌شود.",
        "robots.txt راهنمای خزنده است نه کنترل دسترسی؛ فهرست مسیرها فقط سرنخ است و دسترسی‌پذیری آن‌ها آزمایش نشده است.",
        "sitemap فقط تا ۲۰۰ آدرس هم‌میزبان خوانده می‌شود و آدرس‌های آن به‌صورت خودکار crawl نمی‌شوند."
    )

    suspend fun run(host: String, manifest: WebsiteEngagementManifestV2): PassiveHygieneReportV1 = withContext(Dispatchers.IO) {
        val findings = mutableListOf<Finding>()
        val events = mutableListOf<WebsiteDiscoveryEventV1>()
        var requests = 0
        var lastAt = 0L
        var robots: RobotsInfoV1? = null
        var sitemapCount = 0
        var tlsInfo: TlsSessionInfoV1? = null
        var hstsRaw: String? = null
        var securityTxt: SecurityTxtInfoV1? = null
        val canonical = canonicalHost(host) ?: return@withContext PassiveHygieneReportV1(emptyList(), emptyList(), null, 0, 0, LIMITATIONS)

        suspend fun fetch(url: String): WebsiteDiscoveryEngineV1.PassiveFetchV1? {
            val decision = manifest.authorizeUrl(url, WebsiteTestClassV2.PASSIVE_REVIEW, requests)
            if (!decision.allowed) { events += WebsiteDiscoveryEventV1(url, "BLOCKED_SCOPE", decision.reason); return null }
            if (requests >= manifest.maxRequests) { events += WebsiteDiscoveryEventV1(url, "BUDGET_BLOCKED", "بودجه درخواست مصرف شده است."); return null }
            if (lastAt > 0L) {
                val minimum = (60_000L / manifest.requestsPerMinute.coerceAtLeast(1)).coerceAtMost(60_000L)
                val elapsed = System.currentTimeMillis() - lastAt
                if (elapsed < minimum) delay(minimum - elapsed)
            }
            requests++
            lastAt = System.currentTimeMillis()
            return try {
                WebsiteDiscoveryEngineV1.fetchPassive(decision.normalizedUrl, manifest).also {
                    events += WebsiteDiscoveryEventV1(decision.normalizedUrl, "FETCHED", "HTTP ${it.status}; body=${it.body.length} chars.")
                    if (tlsInfo == null) tlsInfo = it.tls
                    if (hstsRaw == null && decision.normalizedUrl.startsWith("https://", true)) hstsRaw = it.headers["strict-transport-security"]
                }
            } catch (e: Exception) {
                val tls = if (url.startsWith("https://", true)) TlsFailureClassifier.classify(e) else null
                events += if (tls != null) WebsiteDiscoveryEventV1(url, "TLS_VALIDATION_FAILED", "${tls.kind.name}; ${tls.detail}")
                else WebsiteDiscoveryEventV1(url, "REQUEST_FAILED", "${e.javaClass.simpleName}: ${EvidenceSanitizer.sanitize(e.message.orEmpty()).take(160)}")
                null
            }
        }

        // 1) HTTP -> HTTPS (redirect inspected, never followed)
        fetch("http://$canonical/")?.let { r ->
            val location = r.headers["location"]
            val result = HttpsRedirectEvaluatorV1.evaluate(canonical, r.status, location)
            HttpsRedirectEvaluatorV1.toFinding(canonical, result, r.status, location)?.let(findings::add)
        }

        // 2) robots.txt
        val robotsResponse = fetch("https://$canonical/robots.txt")
        if (robotsResponse != null && robotsResponse.status == 200) {
            val info = RobotsTxtV1.parse(robotsResponse.body, canonical)
            robots = info
            if (info.sensitivePathHints.isNotEmpty()) {
                findings += Finding(
                    id = "SG-ROBOTS-SENSITIVE-HINTS", title = "robots.txt مسیرهایی با نام حساس را افشا می‌کند", severity = Severity.INFO,
                    description = "robots.txt عمومی است و هر کسی می‌تواند آن را بخواند؛ فهرست کردن مسیرهایی مثل admin یا backup سرنخ در اختیار مهاجم می‌گذارد. این فایل کنترل دسترسی نیست.",
                    remediation = "دسترسی به مسیرهای حساس را با احراز هویت/فهرست IP محدود کنید و نام آن‌ها را از robots.txt حذف کنید.",
                    confidence = "High", evidence = "Disallow: " + info.sensitivePathHints.take(8).joinToString(", "), cwe = "CWE-200",
                    status = FindingStatus.INFORMATIONAL, affectedAsset = "$canonical:443", exactLocation = "/robots.txt",
                    detectionMethod = "Parsed robots.txt Disallow entries against a keyword list",
                    notTested = "در دسترس بودن یا محافظت‌شدن این مسیرها آزمایش نشد."
                )
            }
        } else if (robotsResponse != null) {
            events += WebsiteDiscoveryEventV1("https://$canonical/robots.txt", "NO_ROBOTS", "HTTP ${robotsResponse.status}")
        }

        // 3) first same-host sitemap (declared in robots.txt, else /sitemap.xml)
        val sitemapUrl = robots?.sitemapUrls?.firstOrNull() ?: "https://$canonical/sitemap.xml"
        val sitemapResponse = fetch(sitemapUrl)
        if (sitemapResponse != null && sitemapResponse.status == 200) {
            sitemapCount = SitemapV1.sameHostLocs(sitemapResponse.body, canonical).size
            events += WebsiteDiscoveryEventV1(sitemapUrl, "SITEMAP_PARSED", (if (SitemapV1.isIndex(sitemapResponse.body)) "sitemap index" else "urlset") + "; same-host URLs=$sitemapCount")
        }

        // 4) security.txt (RFC 9116)
        val secResponse = fetch("https://$canonical/.well-known/security.txt")
        if (secResponse != null) {
            val parsed = if (secResponse.status == 200) SecurityTxtV1.parse(secResponse.body) else null
            securityTxt = parsed
            findings += SecurityTxtV1.evaluate(canonical, secResponse.status, parsed)
        }

        val hstsInfo = hstsRaw?.let { HstsPolicyV1.parse(it) }
        hstsInfo?.let { findings += HstsPolicyV1.evaluate(canonical, it) }
        tlsInfo?.let { findings += TlsSessionEvaluatorV1.evaluate(canonical, it) }
        PassiveHygieneReportV1(findings, events, robots, sitemapCount, requests, LIMITATIONS, tlsInfo, canonical, securityTxt, hstsInfo)
    }
}
