package com.siteguard.app.core

data class WeaknessKnowledge(
    val cwe: String,
    val name: String,
    val summary: String,
    val prevention: String
)

/** Curated starter knowledge. It is not a complete or live CVE database. */
object SecurityKnowledgeBase : KnowledgeProviderV1 {
    override val contractVersion: Int get() = 1
    override fun version(): String = VERSION
    override fun lookup(cwe: String): WeaknessKnowledge? = find(cwe)
    const val VERSION = "2026.11-starter"
    val entries = listOf(
        WeaknessKnowledge("CWE-79", "Cross-Site Scripting", "ورودی غیرقابل اعتماد در context مرورگر بدون خنثی‌سازی مناسب نمایش داده می‌شود.", "خروجی را متناسب با context encode و در صورت نیاز HTML را با sanitizer معتبر پاک‌سازی کنید."),
        WeaknessKnowledge("CWE-89", "SQL Injection", "داده ورودی به‌صورت ناامن وارد دستور SQL می‌شود.", "از prepared statements و پارامترهای bind شده استفاده کنید."),
        WeaknessKnowledge("CWE-78", "OS Command Injection", "داده کنترل‌نشده در فرمان سیستم‌عامل تفسیر می‌شود.", "از shell اجتناب و آرگومان‌های ثابت و allowlist استفاده کنید."),
        WeaknessKnowledge("CWE-502", "Deserialization of Untrusted Data", "داده غیرقابل اعتماد به شیء/ساختار اجرایی تبدیل می‌شود.", "قالب داده غیر اجرایی مانند JSON و اعتبارسنجی schema را ترجیح دهید."),
        WeaknessKnowledge("CWE-798", "Hard-coded Credentials", "اعتبارنامه یا راز در کد یا فایل پیکربندی ثابت قرار گرفته است.", "از Secret Manager استفاده و کلید افشاشده را rotate کنید."),
        WeaknessKnowledge("CWE-22", "Path Traversal", "مسیر فایل با ورودی کنترل‌نشده ساخته می‌شود.", "از شناسه‌های نگاشت‌شده، canonical path و محدودسازی به پوشه مجاز استفاده کنید."),
        WeaknessKnowledge("CWE-352", "CSRF", "درخواست حساس بدون اثبات قصد کاربر قابل اجراست.", "از CSRF token، SameSite و کنترل Origin متناسب استفاده کنید."),
        WeaknessKnowledge("CWE-918", "SSRF", "سرور درخواست را به مقصدی می‌فرستد که کاربر کنترل می‌کند.", "مقصدها را allowlist و دسترسی به شبکه‌های داخلی/metadata را مسدود کنید."),
        WeaknessKnowledge("CWE-862", "Missing Authorization", "عملیات حساس بدون بررسی مجوز سمت سرور انجام می‌شود.", "مجوز را در هر درخواست و برای هر شیء در سمت سرور بررسی کنید."),
        WeaknessKnowledge("CWE-306", "Missing Authentication", "عملکرد حساس بدون احراز هویت قابل دسترسی است.", "برای هر مسیر حساس احراز هویت و کنترل نشست را الزامی کنید."),
        WeaknessKnowledge("CWE-434", "Unrestricted Upload of File with Dangerous Type", "فایل بارگذاری‌شده بدون کنترل نوع/محتوا ممکن است به‌عنوان محتوای اجرایی تفسیر شود.", "نوع واقعی فایل، اندازه، nonce، محل ذخیره و مجوز دسترسی را کنترل کنید و فایل اجرایی را از webroot جدا نگه دارید."),
        WeaknessKnowledge("CWE-345", "Insufficient Verification of Data Authenticity", "داده callback یا webhook بدون بررسی اصالت ممکن است پذیرفته شود.", "امضای پیام را طبق قرارداد سرویس با مقایسه امن، زمان/nonce و کنترل replay بررسی کنید."),
        WeaknessKnowledge("CWE-749", "Exposed Dangerous Method or Function", "قابلیت حساس از طریق رابط عمومی ممکن است بدون محدودسازی قابل دسترس باشد.", "سطح API عمومی را کاهش دهید و مجوز، اعتبارسنجی ورودی و محدودیت دسترسی را اعمال کنید.")
    )
    fun find(cwe: String): WeaknessKnowledge? = entries.firstOrNull { it.cwe.equals(cwe.trim(), ignoreCase = true) }

    /** Offline deterministic lookup; this curated starter catalogue is not SQLite/FTS or a full CVE feed. */
    fun search(query: String, limit: Int = 20): List<WeaknessKnowledge> {
        if (query.isBlank() || limit !in 1..100) return emptyList()
        val tokens = query.lowercase().split(Regex("[^a-z0-9-]+" )).filter { it.length >= 2 }
        if (tokens.isEmpty()) return entries.filter { it.cwe.equals(query.trim(), true) }.take(limit)
        val ranked = entries.mapNotNull { item: WeaknessKnowledge ->
            val haystack = "${item.cwe} ${item.name} ${item.summary} ${item.prevention}".lowercase()
            val score = tokens.fold(0) { total, token ->
                total + when {
                    item.cwe.lowercase() == token -> 5
                    item.name.lowercase().contains(token) -> 3
                    haystack.contains(token) -> 1
                    else -> 0
                }
            }
            if (score > 0) Pair(item, score) else null
        }
        return ranked.sortedByDescending { it.second }.take(limit).map { it.first }
    }
}
