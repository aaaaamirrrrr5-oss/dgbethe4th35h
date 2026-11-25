package com.siteguard.app.core

/**
 * Local, heuristic source-code audit. Findings are leads for manual review,
 * not proof of exploitability. It never executes or modifies the supplied code.
 */
data class CodeAuditResult(
    val fileName: String,
    val language: String,
    val findings: List<Finding>,
    val linesScanned: Int,
    val rootCauseSummary: List<String>
)

/** Language label for dotenv-style files; they get a dedicated secret check instead of the code rules. */
const val ENV_FILE_LANGUAGE = "Environment file"

/**
 * True for real environment files (`.env`, `.env.production`, `prod.env`). Template files that conventionally hold
 * placeholders (`.env.example`, `.env.sample`, `.env.dist`, `.env.template`) are excluded.
 */
fun isEnvFileName(fileName: String): Boolean {
    val name = fileName.substringAfterLast('/').lowercase()
    if (name == ".env" || name.endsWith(".env")) return true
    if (!name.startsWith(".env.")) return false
    return name.substringAfterLast('.') !in setOf("example", "sample", "dist", "template", "tpl", "md", "bak")
}

class SourceCodeAnalyzer {
    private val envSecretLine = Regex(
        "(?i)^\\s*(?:export\\s+)?([A-Z0-9_.-]*(?:SECRET|PASSWORD|PASSWD|PWD|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|AUTH[_-]?KEY|SALT)[A-Z0-9_.-]*)\\s*=\\s*(.*)$"
    )
    private val envPlaceholders = setOf(
        "changeme", "change_me", "change-me", "password", "secret", "example", "null", "none", "true", "false", "todo", "undefined"
    )

    /** Returns the secret-like value of one dotenv line, or null when the line is a comment, empty or a placeholder. */
    private fun envSecretName(line: String): String? {
        val match = envSecretLine.find(line) ?: return null
        var value = match.groupValues[2].trim()
        value = when {
            value.startsWith('"') || value.startsWith('\'') -> value.drop(1).substringBefore(value.first())
            else -> value.substringBefore(" #").trim()
        }
        val lower = value.lowercase()
        if (value.length < 8 || lower in envPlaceholders) return null
        if (value.startsWith('$') || value.startsWith('<') || lower.startsWith("your") || lower.startsWith("change") ||
            value.all { it == '*' || it == 'x' || it == 'X' } || value.all { it.isDigit() }) return null
        return match.groupValues[1]
    }

    private data class Rule(
        val id: String, val title: String, val severity: Severity, val cwe: String,
        val pattern: Regex, val explanation: String, val fix: String,
        val confidence: String = "Medium"
    )

    private val rules = listOf(
        Rule("SG-CODE-PHP-001", "احتمال SQL Injection در PHP", Severity.HIGH, "CWE-89",
            Regex("""(?i)(mysql_query|mysqli_query|->query)\s*\([^;\n]*(\.\s*\${'$'}|\${'$'}[A-Za-z_])"""),
            "ساخت query با الحاق متغیر دیده شد. اگر مقدار از ورودی کنترل‌نشده برسد، خطر SQL Injection وجود دارد.",
            "از Prepared Statements و پارامترهای bind شده استفاده کنید؛ ورودی را صرفاً با escape جایگزین نکنید."),
        Rule("SG-CODE-PHP-006", "احتمال SQL Injection در ساخت query", Severity.HIGH, "CWE-89",
            Regex("""(?i)\b(SELECT|INSERT|UPDATE|DELETE)\b[^;\n]*(\.\s*\${'$'}|\${'$'}_(GET|POST|REQUEST))"""),
            "در خط ساخت query، دستور SQL با الحاق یا ورودی درخواست ترکیب شده است؛ مسیر داده باید بررسی شود.",
            "از Prepared Statements استفاده کنید و ورودی را به‌عنوان پارامتر bind کنید."),
        Rule("SG-CODE-PHP-002", "تابع اجرای فرمان در PHP", Severity.HIGH, "CWE-78",
            Regex("""(?i)\b(exec|shell_exec|system|passthru|popen)\s*\("""),
            "تابع اجرای فرمان سیستم‌عامل در فایل دیده شد؛ وجود تابع به‌تنهایی اثبات آسیب‌پذیری نیست.",
            "در صورت امکان حذف کنید؛ در غیر این صورت از APIهای امن، allowlist سخت‌گیرانه و آرگومان‌بندی بدون shell استفاده کنید."),
        Rule("SG-CODE-PHP-003", "احتمال اجرای کد پویا در PHP", Severity.HIGH, "CWE-95",
            Regex("""(?i)\beval\s*\("""),
            "eval می‌تواند رشته را به‌عنوان کد اجرا کند.",
            "eval را حذف و منطق را به توابع صریح و ورودی‌های محدود تبدیل کنید."),
        Rule("SG-CODE-PHP-004", "احتمال include با مسیر پویا", Severity.MEDIUM, "CWE-98",
            Regex("""(?i)\b(include|include_once|require|require_once)\s*\(?\s*[^;\n]*(\${'$'}_(GET|POST|REQUEST)|\${'$'}[A-Za-z_]\w*)"""),
            "مسیر include/require ظاهراً از متغیر ساخته می‌شود؛ منبع و اعتبارسنجی مسیر باید بررسی شود.",
            "از نگاشت ثابت شناسه به فایل استفاده کنید؛ مسیر را با allowlist محدود کنید و realpath را کنترل کنید."),
        Rule("SG-CODE-PHP-005", "استفاده از unserialize در PHP", Severity.MEDIUM, "CWE-502",
            Regex("""(?i)\bunserialize\s*\("""),
            "unserialize روی داده نامطمئن می‌تواند به زنجیره gadget و اجرای رفتار ناخواسته منجر شود.",
            "از قالب داده امن مانند JSON استفاده کنید؛ اگر اجتناب‌ناپذیر است، کلاس‌های مجاز را محدود و منشأ داده را بررسی کنید."),
        Rule("SG-CODE-JS-001", "احتمال DOM XSS با innerHTML", Severity.MEDIUM, "CWE-79",
            Regex("""(?i)\.innerHTML\s*="""),
            "مقداردهی innerHTML دیده شد؛ اگر داده غیرقابل اعتماد وارد شود، DOM XSS ممکن است.",
            "برای متن از textContent استفاده کنید؛ برای HTML لازم، sanitization معتبر و context-aware انجام دهید."),
        Rule("SG-CODE-JS-002", "استفاده از document.write", Severity.MEDIUM, "CWE-79",
            Regex("""(?i)\bdocument\.write\s*\("""),
            "document.write می‌تواند محتوای پویا را وارد سند کند.",
            "از APIهای امن DOM مانند createElement و textContent استفاده کنید."),
        Rule("SG-CODE-JS-003", "احتمال اجرای کد پویا در JavaScript", Severity.HIGH, "CWE-95",
            Regex("""(?i)\beval\s*\(|new\s+Function\s*\("""),
            "اجرای کد پویا دیده شد؛ داده کنترل‌نشده در این مسیر می‌تواند به اجرای کد منجر شود.",
            "اجرای رشته به‌عنوان کد را حذف و از توابع/نگاشت‌های ثابت استفاده کنید."),
        Rule("SG-CODE-PY-001", "subprocess با shell=True", Severity.HIGH, "CWE-78",
            Regex("""(?i)subprocess\.(run|Popen|call|check_output)\s*\([^)\n]*shell\s*=\s*True"""),
            "اجرای subprocess با shell=True دیده شد؛ الحاق ورودی کاربر خطر تزریق فرمان دارد.",
            "shell=False استفاده کنید و آرگومان‌ها را به‌صورت لیست ارسال کنید؛ ورودی‌ها را allowlist کنید."),
        Rule("SG-CODE-PY-002", "بارگذاری pickle", Severity.HIGH, "CWE-502",
            Regex("""(?i)\bpickle\.(load|loads)\s*\("""),
            "pickle می‌تواند هنگام deserialize کد دلخواه اجرا کند؛ فقط داده کاملاً مورد اعتماد باید بارگذاری شود.",
            "برای داده نامطمئن از JSON یا قالب غیر اجرایی استفاده کنید."),
        Rule("SG-CODE-PY-003", "بارگذاری YAML با loader نامشخص", Severity.MEDIUM, "CWE-502",
            Regex("""(?i)yaml\.load\s*\("""),
            "yaml.load بدون SafeLoader یا Loader امن می‌تواند خطر deserialize داشته باشد.",
            "از yaml.safe_load استفاده کنید و نسخه کتابخانه را به‌روز نگه دارید."),
        Rule("SG-CODE-SECRET-001", "احتمال Secret یا کلید ثابت در سورس", Severity.HIGH, "CWE-798",
            Regex("""(?i)(api[_-]?key|secret[_-]?key|password|access[_-]?token)\s*[:=]\s*["'][A-Za-z0-9_\-\/+=]{12,}["']"""),
            "رشته‌ای شبیه credential ثابت در کد دیده شد؛ ممکن است نمونه/مقدار آزمایشی باشد.",
            "کلید را از کد خارج کنید، از Secret Manager/متغیر محیطی استفاده کنید و اگر واقعی بوده آن را rotate کنید."),
        Rule("SG-CODE-CRYPTO-001", "الگوریتم هش ضعیف یا قدیمی", Severity.MEDIUM, "CWE-328",
            Regex("""(?i)\b(md5|sha1)\s*\("""),
            "استفاده از MD5 یا SHA-1 دیده شد؛ کاربرد دقیق باید بررسی شود.",
            "برای رمز عبور از Argon2id/bcrypt/scrypt و برای یکپارچگی از SHA-256 یا بهتر استفاده کنید."),
        Rule("SG-CODE-JVM-001", "اجرای فرایند سیستم‌عامل در JVM", Severity.HIGH, "CWE-78",
            Regex("""(?i)(Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\("""),
            "API اجرای فرایند در Java/Kotlin دیده شد؛ ورود داده کاربر به آرگومان‌ها می‌تواند خطرناک باشد.",
            "از APIهای بدون shell، آرگومان‌های ثابت و allowlist استفاده کنید و ورودی کاربر را مستقیم به فرمان ندهید."),
        Rule("SG-CODE-JVM-002", "فعال‌سازی JavaScript در WebView", Severity.MEDIUM, "CWE-749",
            Regex("""(?i)javaScriptEnabled\s*=\s*true"""),
            "JavaScript در WebView فعال می‌شود؛ امنیت به محتوای بارگذاری‌شده و bridgeها بستگی دارد.",
            "فقط محتوای مورد اعتماد را بارگذاری کنید، bridge را محدود و navigation را allowlist کنید."),
        Rule("SG-CODE-CSHARP-001", "اجرای فرایند در .NET", Severity.HIGH, "CWE-78",
            Regex("""(?i)Process\.Start\s*\("""),
            "Process.Start دیده شد؛ آرگومان‌ها و منبع داده باید بررسی شوند.",
            "از ProcessStartInfo با UseShellExecute=false، آرگومان‌بندی امن و allowlist استفاده کنید."),
        Rule("SG-CODE-GO-001", "اجرای فرمان در Go", Severity.MEDIUM, "CWE-78",
            Regex("""(?i)exec\.Command(Context)?\s*\("""),
            "exec.Command دیده شد؛ وجود آن به‌تنهایی آسیب‌پذیری نیست، منبع آرگومان‌ها را بررسی کنید.",
            "از shell برای ساخت فرمان استفاده نکنید و آرگومان‌ها را جداگانه و از allowlist بسازید.")
    )

    private companion object { const val MAX_MATCH_WINDOW = 4_000 }

    fun analyze(fileName: String, source: String): CodeAuditResult {
        val language = if (isEnvFileName(fileName)) ENV_FILE_LANGUAGE else when (fileName.substringAfterLast('.', "").lowercase()) {
            "php", "phtml" -> "PHP"
            "js", "jsx", "mjs", "cjs" -> "JavaScript"
            "ts", "tsx" -> "TypeScript"
            "py" -> "Python"
            "java", "kt", "kts" -> "Java/Kotlin"
            "cs" -> "C#"
            "go" -> "Go"
            else -> "Unknown"
        }
        val lines = source.lines()
        val findings = mutableListOf<Finding>()
        val supported = when (language) {
            "PHP" -> setOf("SG-CODE-PHP-001", "SG-CODE-PHP-002", "SG-CODE-PHP-003", "SG-CODE-PHP-006", "SG-CODE-PHP-004", "SG-CODE-PHP-005", "SG-CODE-SECRET-001", "SG-CODE-CRYPTO-001")
            "JavaScript", "TypeScript" -> setOf("SG-CODE-JS-001", "SG-CODE-JS-002", "SG-CODE-JS-003", "SG-CODE-SECRET-001", "SG-CODE-CRYPTO-001")
            "Python" -> setOf("SG-CODE-PY-001", "SG-CODE-PY-002", "SG-CODE-PY-003", "SG-CODE-SECRET-001", "SG-CODE-CRYPTO-001")
            "Java/Kotlin" -> setOf("SG-CODE-JVM-001", "SG-CODE-JVM-002", "SG-CODE-SECRET-001", "SG-CODE-CRYPTO-001")
            "C#" -> setOf("SG-CODE-CSHARP-001", "SG-CODE-SECRET-001", "SG-CODE-CRYPTO-001")
            "Go" -> setOf("SG-CODE-GO-001", "SG-CODE-SECRET-001", "SG-CODE-CRYPTO-001")
            ENV_FILE_LANGUAGE -> emptySet()
            else -> rules.map { it.id }.toSet()
        }
        lines.forEachIndexed { index, line ->
            if (line.trimStart().startsWith("//") || line.trimStart().startsWith("#") || line.trimStart().startsWith("*")) return@forEachIndexed
            // Minified/generated files can be one multi-hundred-KB line; regexes such as `[^;\n]*` then degrade to
            // quadratic time. Match in bounded windows so a hostile or minified file cannot stall the scan.
            val segments = if (line.length <= MAX_MATCH_WINDOW) listOf(line) else line.chunked(MAX_MATCH_WINDOW)
            rules.filter { rule -> rule.id in supported && segments.any { rule.pattern.containsMatchIn(it) } }.forEach { rule ->
                findings += Finding(
                    id = "${rule.id}-L${index + 1}",
                    title = rule.title,
                    severity = rule.severity,
                    description = "${rule.explanation} محل: $fileName:${index + 1}",
                    remediation = rule.fix,
                    confidence = rule.confidence,
                    evidence = EvidenceSanitizer.sanitize(line.trim()).take(220),
                    cwe = rule.cwe,
                    status = FindingStatus.PROBABLE,
                    affectedAsset = fileName,
                    exactLocation = "$fileName:${index + 1}",
                    detectionMethod = "Deterministic line-pattern source analysis",
                    businessImpact = "در صورت قابل کنترل بودن ورودی و رسیدن به مسیر حساس، ممکن است بر محرمانگی، یکپارچگی یا دسترس‌پذیری اثر بگذارد.",
                    exploitPrerequisites = "منبع ورودی، مسیر داده و کنترل‌های پیرامونی هنوز اثبات نشده‌اند.",
                    safeValidation = "مسیر داده و اعتبارسنجی را با بازبینی کد و تست واحد غیرمخرب بررسی کنید.",
                    notTested = "کد اجرا نشده و AST، taint analysis، framework routing و dependency resolution انجام نشده‌اند."
                )
            }
        }
        if (language == ENV_FILE_LANGUAGE) {
            lines.forEachIndexed { index, line ->
                if (line.trimStart().startsWith("#")) return@forEachIndexed
                val name = envSecretName(line) ?: return@forEachIndexed
                findings += Finding(
                    id = "SG-CODE-ENV-001-L${index + 1}",
                    title = "احتمال Secret ثابت در فایل محیطی (.env)",
                    severity = Severity.HIGH,
                    description = "متغیر $name در فایل محیطی مقدار ثابت و غیر-placeholder دارد. محل: $fileName:${index + 1}",
                    remediation = "فایل .env را از مخزن و آرشیو قابل انتشار خارج کنید، مقدار را اگر واقعی بوده rotate کنید، از Secret Manager یا متغیر محیطی سرویس استفاده کنید و دسترسی وب به این فایل را مسدود کنید.",
                    confidence = "Medium",
                    // Only the variable name is kept; the value is never copied into evidence.
                    evidence = "$name=[REDACTED]",
                    cwe = "CWE-798",
                    status = FindingStatus.PROBABLE,
                    affectedAsset = fileName,
                    exactLocation = "$fileName:${index + 1}",
                    detectionMethod = "Deterministic dotenv secret-name pattern analysis",
                    businessImpact = "اگر مقدار واقعی باشد و فایل در دسترس مهاجم قرار گیرد، ممکن است به سرویس‌ها یا داده‌های وابسته دسترسی داده شود.",
                    exploitPrerequisites = "واقعی بودن مقدار و در دسترس بودن فایل (مخزن، آرشیو یا مسیر وب) هنوز اثبات نشده است.",
                    safeValidation = "بدون استفاده از مقدار برای ورود، وجود فایل در مخزن/آرشیو و دسترسی وب به آن را بازبینی کنید.",
                    notTested = "اعتبار مقدار، دامنه دسترسی آن و در معرض بودن فایل روی سرور بررسی نشده است."
                )
            }
        }
        val grouped = findings.groupBy { it.cwe }.map { (cwe, items) ->
            "$cwe: ${items.size} نشانه؛ بررسی مسیر داده و کنترل‌های ورودی مرتبط پیشنهاد می‌شود."
        }
        return CodeAuditResult(fileName, language, findings.distinctBy { it.id }, lines.size, grouped)
    }
}
