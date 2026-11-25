package com.siteguard.app.core

import org.json.JSONObject
import java.net.IDN
import java.net.URLEncoder
import java.net.URL
import javax.net.ssl.HttpsURLConnection

/** Passive DNS posture checks using DNS-over-HTTPS JSON. No DNS record is changed. */
enum class DnsPostureStateV1 { PASS, WARNING, CRITICAL, UNKNOWN }

data class DnsPostureCheckV1(
    val id: String,
    val title: String,
    val state: DnsPostureStateV1,
    val detail: String,
    val evidence: List<String> = emptyList()
)

data class DnsPostureResultV1(
    val domain: String,
    val checkedAtEpochMs: Long,
    val resolver: String,
    val checks: List<DnsPostureCheckV1>,
    val limitations: List<String>
)

object DnsSecurityPostureAnalyzerV1 {
    private const val RESOLVER = "https://dns.google/resolve"
    private const val MAX_RESPONSE_BYTES = 256 * 1024

    fun analyze(
        input: String,
        nowEpochMs: Long = System.currentTimeMillis(),
        recordResolver: (String, Int) -> List<String> = ::queryRecords
    ): DnsPostureResultV1 {
        val domain = normalizeDomain(input)
        val txt = DnsAnswer(recordResolver(domain, 16))
        val dmarc = DnsAnswer(recordResolver("_dmarc.$domain", 16))
        val caa = DnsAnswer(recordResolver(domain, 257))
        val checks = mutableListOf<DnsPostureCheckV1>()

        val spfRecords = txt.records.filter { it.trim().trim('"').startsWith("v=spf1", true) }
        checks += when {
            spfRecords.isEmpty() -> DnsPostureCheckV1("SPF", "سیاست SPF", DnsPostureStateV1.WARNING,
                "رکورد SPF پیدا نشد؛ ارسال ایمیل از دامنه ممکن است در برابر جعل فرستنده آسیب‌پذیرتر باشد.")
            spfRecords.size > 1 -> DnsPostureCheckV1("SPF", "سیاست SPF", DnsPostureStateV1.CRITICAL,
                "بیش از یک رکورد SPF دیده شد؛ چند رکورد SPF در یک نام دامنه می‌تواند باعث خطای ارزیابی شود.", spfRecords)
            else -> {
                val record = spfRecords.single()
                val includes = Regex("(?i)\\binclude:").findAll(record).count()
                val terminal = Regex("(?i)\\s([~?+.-]all)\\b").find(record)?.groupValues?.getOrNull(1)?.lowercase()
                when {
                    includes > 10 -> DnsPostureCheckV1("SPF", "سیاست SPF", DnsPostureStateV1.WARNING,
                        "بیش از ۱۰ سازوکار include دیده شد؛ تعداد lookupهای DNS باید در تمام زنجیره بررسی شود.", spfRecords)
                    terminal == "+all" -> DnsPostureCheckV1("SPF", "سیاست SPF", DnsPostureStateV1.CRITICAL,
                        "پایان +all همه فرستنده‌ها را مجاز می‌کند و معمولاً سیاست ناامن است.", spfRecords)
                    terminal == "?all" -> DnsPostureCheckV1("SPF", "سیاست SPF", DnsPostureStateV1.WARNING,
                        "پایان ?all نتیجه را خنثی می‌کند؛ سخت‌گیری سیاست باید بررسی شود.", spfRecords)
                    terminal == "~all" -> DnsPostureCheckV1("SPF", "سیاست SPF", DnsPostureStateV1.WARNING,
                        "SPF با ~all پایان می‌یابد؛ این حالت softfail است و باید با طراحی ارسال ایمیل تطبیق داده شود.", spfRecords)
                    terminal == "-all" -> DnsPostureCheckV1("SPF", "سیاست SPF", DnsPostureStateV1.PASS,
                        "یک رکورد SPF با سیاست -all پیدا شد؛ صحت تمام includeها و منابع مجاز همچنان نیازمند بازبینی است.", spfRecords)
                    else -> DnsPostureCheckV1("SPF", "سیاست SPF", DnsPostureStateV1.WARNING,
                        "رکورد SPF وجود دارد، اما سازوکار پایانی all به‌وضوح تشخیص داده نشد.", spfRecords)
                }
            }
        }

        val dmarcRecords = dmarc.records.filter { it.trim().trim('"').startsWith("v=DMARC1", true) }
        checks += when {
            dmarcRecords.isEmpty() -> DnsPostureCheckV1("DMARC", "سیاست DMARC", DnsPostureStateV1.WARNING,
                "رکورد DMARC در _dmarc پیدا نشد.")
            dmarcRecords.size > 1 -> DnsPostureCheckV1("DMARC", "سیاست DMARC", DnsPostureStateV1.CRITICAL,
                "چند رکورد DMARC پیدا شد؛ فقط یک رکورد سیاست معتبر باید منتشر شود.", dmarcRecords)
            else -> {
                val record = dmarcRecords.single()
                val policy = Regex("(?i)(?:^|;)\\s*p\\s*=\\s*([a-z]+)").find(record)?.groupValues?.getOrNull(1)?.lowercase()
                when (policy) {
                    "reject" -> DnsPostureCheckV1("DMARC", "سیاست DMARC", DnsPostureStateV1.PASS, "سیاست DMARC روی reject تنظیم شده است.", dmarcRecords)
                    "quarantine" -> DnsPostureCheckV1("DMARC", "سیاست DMARC", DnsPostureStateV1.PASS, "سیاست DMARC روی quarantine تنظیم شده است.", dmarcRecords)
                    "none" -> DnsPostureCheckV1("DMARC", "سیاست DMARC", DnsPostureStateV1.WARNING, "سیاست DMARC روی none است؛ این حالت عمدتاً پایش می‌کند و به‌تنهایی جلوی جعل را نمی‌گیرد.", dmarcRecords)
                    else -> DnsPostureCheckV1("DMARC", "سیاست DMARC", DnsPostureStateV1.WARNING, "رکورد DMARC وجود دارد، اما مقدار p معتبر یا قابل تشخیص نیست.", dmarcRecords)
                }
            }
        }

        checks += when {
            caa.records.isEmpty() -> DnsPostureCheckV1("CAA", "محدودیت صادرکنندگان گواهی (CAA)", DnsPostureStateV1.WARNING,
                "رکورد CAA مشاهده نشد؛ در نتیجه محدودیت DNS برای CAها از این بررسی قابل تأیید نیست.")
            else -> DnsPostureCheckV1("CAA", "محدودیت صادرکنندگان گواهی (CAA)", DnsPostureStateV1.PASS,
                "رکورد(های) CAA پیدا شد؛ صادرکنندگان و مجوزهای issue/issuewild را با سیاست سازمان تطبیق دهید.", caa.records)
        }

        return DnsPostureResultV1(
            domain, nowEpochMs, "Google Public DNS-over-HTTPS",
            checks,
            listOf(
                "این آزمون فقط چند رکورد عمومی DNS را از طریق resolver ثالث می‌خواند؛ کل DNS zone یا زنجیره کامل SPF را بررسی نمی‌کند.",
                "نبود پاسخ یا خطای resolver معادل نبود رکورد نیست؛ برای تغییر سیاست ایمیل یا CAA با مدیر دامنه هماهنگ کنید.",
                "رکوردهای مشاهده‌شده باید با ارائه‌دهنده ایمیل، DNS و سیاست واقعی سازمان تطبیق داده شوند."
            )
        )
    }

    private fun normalizeDomain(input: String): String {
        val raw = input.trim().replace(Regex("(?i)^https?://"), "").substringBefore('/').substringBefore(':').trimEnd('.')
        require(raw.isNotBlank() && raw.length <= 253 && !raw.contains('*')) { "نام دامنه معتبر وارد کنید." }
        val ascii = IDN.toASCII(raw, IDN.USE_STD3_ASCII_RULES).lowercase()
        require(ascii.contains('.') && ascii.split('.').all { it.isNotBlank() && it.length <= 63 }) { "برای بررسی DNS یک دامنه کامل وارد کنید." }
        require(!Regex("^\\d{1,3}(?:\\.\\d{1,3}){3}$").matches(ascii) && !ascii.contains(':')) { "این ابزار برای نام دامنه است، نه IP." }
        return ascii
    }

    private data class DnsAnswer(val records: List<String>)

    private fun queryRecords(name: String, type: Int): List<String> = query(name, type).records

    private fun query(name: String, type: Int): DnsAnswer {
        val encoded = URLEncoder.encode(name, Charsets.UTF_8.name())
        val connection = (URL("$RESOLVER?name=$encoded&type=$type").openConnection() as HttpsURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 5_000
            readTimeout = 5_000
            instanceFollowRedirects = false
            useCaches = false
            setRequestProperty("Accept", "application/dns-json")
            setRequestProperty("User-Agent", SiteGuardBuildInfo.USER_AGENT)
        }
        try {
            val status = connection.responseCode
            require(status == HttpsURLConnection.HTTP_OK) { "DNS resolver پاسخ HTTP $status برگرداند." }
            val bytes = connection.inputStream.use { stream ->
                val out = java.io.ByteArrayOutputStream()
                val buffer = ByteArray(4096)
                var total = 0
                while (true) {
                    val count = stream.read(buffer)
                    if (count < 0) break
                    total += count
                    require(total <= MAX_RESPONSE_BYTES) { "پاسخ DNS بیش از حد بزرگ است." }
                    out.write(buffer, 0, count)
                }
                out.toByteArray()
            }
            val json = JSONObject(bytes.toString(Charsets.UTF_8))
            val rcode = json.optInt("Status", -1)
            require(rcode == 0 || rcode == 3) { "DNS resolver کد وضعیت $rcode برگرداند." }
            val answers = json.optJSONArray("Answer") ?: return DnsAnswer(emptyList())
            val values = (0 until answers.length()).mapNotNull { index ->
                answers.optJSONObject(index)?.optString("data")?.takeIf { it.isNotBlank() }
            }.distinct()
            return DnsAnswer(values)
        } finally {
            connection.disconnect()
        }
    }
}
