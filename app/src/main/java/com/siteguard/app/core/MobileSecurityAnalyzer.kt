package com.siteguard.app.core

import org.w3c.dom.Element
import org.xml.sax.InputSource
import java.io.StringReader
import javax.xml.XMLConstants
import javax.xml.parsers.DocumentBuilderFactory

/** Offline Android/mobile source review. Compiled binary AXML and runtime-only behavior are explicitly unsupported. */
object MobileSecurityAnalyzer {
    private const val ANDROID_NS = "http://schemas.android.com/apk/res/android"

    fun analyze(files: Map<String, String>): List<Finding> {
        val out = mutableListOf<Finding>()
        val manifestEntry = files.entries.firstOrNull { it.key.substringAfterLast('/').equals("AndroidManifest.xml", true) }
        if (manifestEntry != null) analyzeManifest(manifestEntry.key, manifestEntry.value, out)

        files.forEach { (path, text) ->
            val lowerPath = path.lowercase()
            if (lowerPath.endsWith("network_security_config.xml")) analyzeNetworkConfig(path, text, out)
            val ext = path.substringAfterLast('.', "").lowercase()
            if (ext in setOf("kt", "java", "xml")) analyzeSourcePatterns(path, text, out)
            if (lowerPath.endsWith("build.gradle") || lowerPath.endsWith("build.gradle.kts") || lowerPath.endsWith("gradle.properties")) {
                analyzeBuildConfig(path, text, out)
            }
        }
        return out.distinctBy { it.id }
    }

    private fun analyzeManifest(path: String, xml: String, out: MutableList<Finding>) {
        if (xml.isBlank() || xml.firstOrNull() != '<') {
            out += finding("SG-MOB-AXML", path, 1, "AndroidManifest باینری یا غیرقابل‌خواندن است", Severity.INFO, "",
                "این ورودی به XML متنی قابل‌تحلیل تبدیل نشده است.",
                "Manifest را از سورس/خروجی decoded معتبر ارائه کنید یا ابزار تحلیل موبایل سازگار را در محیط جداگانه اجرا کنید.",
                "فرمت باینری AXML در این parser پشتیبانی نمی‌شود؛ هیچ نتیجه امنیتی از آن استخراج نشده است.", FindingStatus.INFORMATIONAL)
            return
        }
        val document = runCatching {
            val factory = DocumentBuilderFactory.newInstance().apply {
                isNamespaceAware = true
                isXIncludeAware = false
                setExpandEntityReferences(false)
                setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
                setFeature("http://xml.org/sax/features/external-general-entities", false)
                setFeature("http://xml.org/sax/features/external-parameter-entities", false)
                setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "")
                setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "")
            }
            factory.newDocumentBuilder().parse(InputSource(StringReader(xml)))
        }.getOrNull()
        if (document == null) {
            out += finding("SG-MOB-MANIFEST-PARSE", path, 1, "AndroidManifest قابل‌تجزیه نیست", Severity.INFO, "",
                "XML متنی Manifest با parser امن قابل‌خواندن نبود.", "فایل XML معتبر و کامل را دوباره بررسی کنید.",
                "اجزای Manifest و attributeها بررسی نشده‌اند.", FindingStatus.UNVERIFIED)
            return
        }
        val root = document.documentElement ?: return
        val app = root.getElementsByTagName("application").let { if (it.length > 0) it.item(0) as? Element else null }
        fun attr(element: Element?, name: String): String = element?.let {
            it.getAttributeNS(ANDROID_NS, name).ifBlank { it.getAttribute("android:$name") }
        }.orEmpty()
        val targetSdk = root.getElementsByTagName("uses-sdk").let { nodes ->
            if (nodes.length > 0) attr(nodes.item(0) as? Element, "targetSdkVersion").toIntOrNull() else null
        }
        if (attr(app, "debuggable").equals("true", true)) {
            out += finding("SG-MOB-DEBUGGABLE", path, 1, "نسخه قابل‌دیباگ در Manifest فعال است", Severity.MEDIUM, "CWE-489",
                "android:debuggable=true", "در build انتشار، debuggable را غیرفعال و تنظیمات release را در pipeline کنترل کنید.",
                "نسخه build و نوع نصب‌شده مشخص نیست؛ ممکن است این Manifest متعلق به debug باشد.")
        }
        if (attr(app, "usesCleartextTraffic").equals("true", true)) {
            out += finding("SG-MOB-CLEARTEXT", path, 1, "ترافیک cleartext در برنامه مجاز شده است", Severity.MEDIUM, "CWE-319",
                "android:usesCleartextTraffic=true", "ارتباطات حساس را فقط با TLS معتبر انجام دهید و allowlist محدود در Network Security Config را ترجیح دهید.",
                "این تنظیم به‌تنهایی ثابت نمی‌کند داده حساس از HTTP ارسال می‌شود.")
        }
        val componentTags = listOf("activity", "activity-alias", "service", "receiver", "provider")
        componentTags.forEach { tag ->
            val nodes = root.getElementsByTagName(tag)
            for (i in 0 until nodes.length) {
                val element = nodes.item(i) as? Element ?: continue
                val exported = attr(element, "exported")
                val hasFilter = element.getElementsByTagName("intent-filter").length > 0
                val name = attr(element, "name").ifBlank { "نامشخص" }
                if (targetSdk != null && targetSdk >= 31 && hasFilter && exported.isBlank()) {
                    out += finding("SG-MOB-EXPORTED-MISSING", path, 1, "کامپوننت دارای intent-filter فاقد android:exported صریح است", Severity.MEDIUM, "CWE-926",
                        "$tag $name; intent-filter موجود؛ exported تعریف نشده", "برای هر component مقدار exported را صریح تعیین کنید و برای اجزای داخلی false بگذارید.",
                        "فقط Manifest متنی بررسی شده؛ merge نهایی Manifest و مقدارهای build variant بررسی نشده‌اند.")
                } else if (exported.equals("true", true) && attr(element, "permission").isBlank()) {
                    out += finding("SG-MOB-EXPORTED-PUBLIC", path, 1, "کامپوننت Android به‌صورت exported و بدون permission تعریف شده است", Severity.LOW, "CWE-926",
                        "$tag $name; exported=true; permission مشاهده نشد", "ضرورت public بودن را بررسی کنید؛ در صورت نیاز permission مناسب و اعتبارسنجی ورودی/Caller اعمال کنید.",
                        "exported بودن ممکن است بخشی از طراحی موردنظر باشد؛ دسترسی واقعی و intent handling در runtime تست نشده است.")
                }
            }
        }
        val permissions = root.getElementsByTagName("uses-permission")
        val sensitive = (0 until permissions.length).mapNotNull { i ->
            val p = permissions.item(i) as? Element ?: return@mapNotNull null
            attr(p, "name").takeIf { it in setOf("android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.RECORD_AUDIO", "android.permission.READ_CONTACTS", "android.permission.ACCESS_FINE_LOCATION", "android.permission.CAMERA") }
        }
        if (sensitive.isNotEmpty()) {
            out += finding("SG-MOB-SENSITIVE-PERMISSIONS", path, 1, "مجوزهای حساس نیازمند توجیه و بازبینی حریم خصوصی هستند", Severity.INFO, "CWE-250",
                sensitive.distinct().joinToString(", "), "اصل کمینه‌سازی داده را اعمال کنید؛ مجوز را فقط هنگام نیاز واقعی و با توضیح روشن درخواست کنید.",
                "وجود permission به معنی استفاده واقعی یا سوءاستفاده نیست.", FindingStatus.INFORMATIONAL)
        }
    }

    private fun analyzeNetworkConfig(path: String, text: String, out: MutableList<Finding>) {
        text.lines().forEachIndexed { i, line ->
            if (Regex("(?i)cleartextTrafficPermitted\\s*=\\s*['\"]?true").containsMatchIn(line)) {
                out += finding("SG-MOB-NETCFG-CLEARTEXT", path, i + 1, "Network Security Config اجازه cleartext می‌دهد", Severity.MEDIUM, "CWE-319",
                    line.trim().take(160), "cleartext را به‌صورت پیش‌فرض رد کنید و فقط دامنه‌های تستی غیرحساس را در صورت ضرورت استثنا کنید.",
                    "ترافیک runtime و دامنه‌های واقعی درخواست‌شده مشاهده نشده‌اند.")
            }
            if (Regex("(?i)<certificates[^>]+src\\s*=\\s*['\"]user['\"]").containsMatchIn(line)) {
                out += finding("SG-MOB-USER-CA-TRUST", path, i + 1, "اعتماد به CA کاربر در پیکربندی TLS دیده شد", Severity.LOW, "CWE-295",
                    "certificates src=user", "اعتماد به CA کاربر را برای build انتشار و دامنه‌های حساس محدود کنید؛ رفتار debug/release را جدا کنید.",
                    "استفاده از CA کاربر در همه نسخه‌ها/دامنه‌ها و رفتار واقعی pinning بررسی نشده است.")
            }
        }
    }

    private fun analyzeSourcePatterns(path: String, text: String, out: MutableList<Finding>) {
        val lines = text.lines()
        lines.forEachIndexed { i, line ->
            val n = i + 1
            if (Regex("addJavascriptInterface\\s*\\(").containsMatchIn(line)) {
                out += finding("SG-MOB-WEBVIEW-BRIDGE", path, n, "پل JavaScript در WebView وجود دارد", Severity.MEDIUM, "CWE-749",
                    "addJavascriptInterface() در خط $n", "فقط متدهای ضروری و کم‌اختیار را با @JavascriptInterface منتشر کنید؛ محتوای remote/untrusted را به WebView دارای bridge ندهید و origin را کنترل کنید.",
                    "قابلیت دسترسی WebView، origin محتوا، APIهای bridge و نسخه Android در runtime بررسی نشده‌اند.")
            }
            if (Regex("setJavaScriptEnabled\\s*\\(\\s*true\\s*\\)").containsMatchIn(line)) {
                out += finding("SG-MOB-WEBVIEW-JS", path, n, "JavaScript در WebView فعال شده است", Severity.INFO, "CWE-749",
                    "setJavaScriptEnabled(true)", "JavaScript را فقط برای WebViewهایی فعال کنید که به آن نیاز دارند؛ navigation و محتوای بارگیری‌شده را محدود کنید.",
                    "فعال بودن JavaScript به‌تنهایی آسیب‌پذیری نیست.", FindingStatus.INFORMATIONAL)
            }
            if (Regex("setAllowFileAccess\\s*\\(\\s*true\\s*\\)").containsMatchIn(line)) {
                out += finding("SG-MOB-WEBVIEW-FILE", path, n, "دسترسی فایل در WebView فعال است", Severity.MEDIUM, "CWE-200",
                    "setAllowFileAccess(true)", "در صورت عدم نیاز file access را غیرفعال کنید و دسترسی فایل/محتوای محلی را از محتوای غیرقابل‌اعتماد جدا نگه دارید.",
                    "ترکیب آن با origin و تنظیمات دیگر WebView در runtime بررسی نشده است.")
            }
            if (Regex("MODE_WORLD_(READABLE|WRITEABLE)").containsMatchIn(line)) {
                out += finding("SG-MOB-WORLD-PREFS", path, n, "الگوی storage قدیمی world-readable/writeable دیده شد", Severity.HIGH, "CWE-732",
                    "استفاده از MODE_WORLD_* در خط $n", "از storage خصوصی اپ و Android Keystore برای رازها استفاده کنید؛ داده‌های قبلی را با کنترل دسترسی امن مهاجرت دهید.",
                    "ممکن است کد قدیمی/غیرفعال باشد؛ دسترسی واقعی روی نسخه هدف تست نشده است.")
            }
        }
    }

    private fun analyzeBuildConfig(path: String, text: String, out: MutableList<Finding>) {
        if (Regex("(?i)minifyEnabled\\s+false").containsMatchIn(text)) {
            out += finding("SG-MOB-MINIFY-DISABLED", path, 1, "کاهش/obfuscation کد در این build غیرفعال است", Severity.INFO, "",
                "minifyEnabled false", "برای release، نیاز به R8 و قواعد نگه‌داری را ارزیابی کنید؛ obfuscation جایگزین کنترل امنیتی نیست.",
                "نوع variant و الزامات انتشار مشخص نیست.", FindingStatus.INFORMATIONAL)
        }
    }

    private fun finding(id: String, path: String, line: Int, title: String, severity: Severity, cwe: String,
                        evidence: String, remediation: String, notTested: String,
                        status: FindingStatus = FindingStatus.PROBABLE): Finding = Finding(
        id = "$id-L$line", title = title, severity = severity,
        description = "نشانه ایستا در فایل $path:$line شناسایی شد؛ برای نتیجه قطعی باید context و variant واقعی بررسی شود.",
        remediation = remediation, confidence = if (status == FindingStatus.INFORMATIONAL) "High" else "Low–Medium",
        evidence = EvidenceSanitizer.sanitize(evidence).take(220), cwe = cwe, status = status,
        affectedAsset = path, exactLocation = "$path:$line", detectionMethod = "Android/mobile deterministic configuration review",
        businessImpact = "بسته به سطح دسترسی component، نوع داده و رفتار برنامه می‌تواند بر محرمانگی/تمامیت/دسترس‌پذیری اثر بگذارد.",
        exploitPrerequisites = "از فایل ایستا به‌تنهایی قابل اثبات نیست.",
        safeValidation = "تنظیم نهایی merge شده و رفتار در emulator/device با fixture امن را بررسی کنید.",
        notTested = notTested,
        verificationProcedure = "تست منفی/مثبت روی build release و debug اجرا و تنظیم موثر را تأیید کنید.",
        expectedResult = "فقط قابلیت‌ها و کامپوننت‌های موردنیاز در نسخه انتشار فعال باشند."
    )
}
