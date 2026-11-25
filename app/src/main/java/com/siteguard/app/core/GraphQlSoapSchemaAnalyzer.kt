package com.siteguard.app.core

import org.w3c.dom.Element
import org.xml.sax.InputSource
import java.io.StringReader
import java.security.MessageDigest
import javax.xml.XMLConstants
import javax.xml.parsers.DocumentBuilderFactory

/** Static schema review only. It never sends requests or attempts authentication bypass. */
object GraphQlSoapSchemaAnalyzer {
    private val sensitiveField = Regex("(?i)(user|account|customer|order|payment|invoice|email|phone|address|token|secret|admin|role|permission|billing|refund|password)")
    private val accessDirectives = Regex("(?i)@(auth|authenticated|requiresRole|hasRole|authorize|permission|ownerOnly|private)")

    fun analyze(files: Map<String, String>): List<Finding> {
        val out = mutableListOf<Finding>()
        files.forEach { (path, text) ->
            val lower = path.lowercase()
            when {
                lower.endsWith(".graphql") || lower.endsWith(".gql") || lower.endsWith(".graphqls") -> out += analyzeGraphQl(path, text)
                lower.endsWith(".wsdl") || lower.endsWith(".xml") && text.contains("definitions", true) && text.contains("wsdl", true) -> out += analyzeWsdl(path, text)
                (lower.endsWith(".yaml") || lower.endsWith(".yml")) && (text.contains("openapi:") || text.contains("swagger:")) -> out += analyzeOpenApiYaml(path, text)
            }
        }
        return out.distinctBy { it.id }
    }

    private fun analyzeGraphQl(path: String, source: String): List<Finding> {
        val findings = mutableListOf<Finding>()
        var activeType = ""
        var typeLevelGuard = false
        var braceDepth = 0
        source.lines().forEachIndexed { index, raw ->
            val line = raw.substringBefore('#').trim()
            if (line.isBlank()) return@forEachIndexed
            val declaration = Regex("^(?:extend\\s+)?type\\s+(Query|Mutation|Subscription)\\b(.*)$", RegexOption.IGNORE_CASE).find(line)
            if (declaration != null) {
                activeType = declaration.groupValues[1]
                typeLevelGuard = accessDirectives.containsMatchIn(declaration.groupValues[2])
                braceDepth = line.count { it == '{' } - line.count { it == '}' }
                return@forEachIndexed
            }
            if (activeType.isNotBlank()) {
                braceDepth += line.count { it == '{' } - line.count { it == '}' }
                val field = Regex("^([_A-Za-z][_0-9A-Za-z]*)\\s*(?:\\([^)]*\\))?\\s*:\\s*([_A-Za-z][_0-9A-Za-z!\\[\\]]*)(.*)$").find(line)
                if (field != null) {
                    val fieldName = field.groupValues[1]
                    val tail = field.groupValues[3]
                    if (sensitiveField.containsMatchIn(fieldName) && !typeLevelGuard && !accessDirectives.containsMatchIn(tail)) {
                        findings += finding(
                            "SG-API-GQL-SENSITIVE-FIELD", path, index + 1,
                            "فیلد حساس GraphQL نیازمند بازبینی کنترل دسترسی است",
                            "در $activeType.$fieldName نشانه نام‌گذاری حساس دیده شد، اما directive دسترسی روی همان خط یا type-level مشاهده نشد. این موضوع اثبات نبود کنترل authorization در runtime نیست.",
                            "برای resolver/service هر field کنترل object-level و role/tenant را سمت سرور enforce کنید؛ صرف پنهان‌سازی field در schema یا UI کافی نیست.",
                            "فقط SDL خط‌محور بررسی شد؛ resolver، middleware، schema stitching و runtime authorization اجرا نشده‌اند."
                        )
                    }
                }
                if (braceDepth <= 0) { activeType = ""; typeLevelGuard = false }
            }
        }
        if (source.contains("__schema") || source.contains("__type")) {
            findings += finding("SG-API-GQL-INTROSPECTION-SDL", path, 1,
                "نام introspection در سند GraphQL دیده شد؛ وضعیت runtime نامشخص است",
                "وجود نام introspection در SDL یا نمونه مستندات، فعال بودن introspection در endpoint را اثبات نمی‌کند.",
                "سیاست introspection را با نیاز توسعه/production تعیین کنید و محدودیت depth/complexity و timeout را در gateway و backend اعمال کنید.",
                "هیچ درخواست GraphQL اجرا نشده و introspection endpoint آزمایش نشده است.", severity = Severity.INFO, status = FindingStatus.INFORMATIONAL)
        }
        return findings
    }

    private fun analyzeWsdl(path: String, xml: String): List<Finding> {
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
        }.getOrNull() ?: return listOf(finding("SG-API-WSDL-PARSE", path, 1, "WSDL قابل‌تجزیه نیست",
            "XML با parser امن قابل‌خواندن نبود یا سند ناقص است.", "WSDL را از منبع معتبر و بدون DTD خارجی تهیه کنید.",
            "هیچ operation یا endpointی استخراج نشده است.", Severity.INFO, FindingStatus.UNVERIFIED))
        val elements = document.getElementsByTagNameNS("*", "address")
        val findings = mutableListOf<Finding>()
        for (i in 0 until elements.length) {
            val element = elements.item(i) as? Element ?: continue
            val location = element.getAttribute("location")
            if (location.startsWith("http://", true)) {
                findings += finding("SG-API-WSDL-HTTP-ENDPOINT", path, i + 1, "آدرس SOAP در WSDL از HTTP استفاده می‌کند",
                    "WSDL یک endpoint با scheme غیررمزشده HTTP اعلام می‌کند.",
                    "در محیط واقعی HTTPS با TLS معتبر را به کار ببرید؛ endpointهای mock/lab را جدا و صریح تعریف کنید.",
                    "وضعیت endpoint اجرایی و TLS واقعی بررسی نشده است.", Severity.MEDIUM, FindingStatus.PROBABLE, evidence = "SOAP address uses http://")
            }
        }
        val operations = document.getElementsByTagNameNS("*", "operation").length
        if (operations > 0 && document.getElementsByTagNameNS("*", "Policy").length == 0 && document.getElementsByTagNameNS("*", "Security").length == 0) {
            findings += finding("SG-API-WSDL-SECURITY-METADATA", path, 1, "WSDL فاقد metadata امنیتی قابل تشخیص است",
                "$operations operation در WSDL دیده شد، اما عنصر امنیتی شناخته‌شده در سند یافت نشد. سیاست ممکن است خارج از WSDL اعمال شود.",
                "احراز هویت، امضای پیام، TLS، مجوز operation و کنترل replay را در مستندات deployment و runtime بررسی کنید.",
                "نبود metadata در WSDL معادل نبود کنترل در runtime نیست.", Severity.INFO, FindingStatus.INFORMATIONAL)
        }
        return findings
    }

    private fun analyzeOpenApiYaml(path: String, source: String): List<Finding> {
        val findings = mutableListOf<Finding>()
        var globalSecurity = false
        var operation = ""
        var operationIndent = -1
        var operationHasSecurity = false
        fun finishOperation(lineNo: Int) {
            if (operation.isNotBlank() && !operationHasSecurity) {
                findings += finding("SG-API-OPENAPI-YAML-NO-SECURITY", path, lineNo,
                    "عملیات OpenAPI YAML فاقد security قابل مشاهده است",
                    "برای $operation، security محلی یا global قابل تشخیص نبود؛ endpoint ممکن است عمداً عمومی باشد.",
                    "برای عملیات خصوصی security scheme را مستند کنید و authorization واقعی را برای هر operation/object/tenant سمت سرور بررسی کنید.",
                    "این بررسی YAML خط‌محور است؛ YAML anchor، merge، ${'$'}ref و inheritance پیچیده resolve نشده‌اند.", Severity.MEDIUM, FindingStatus.PROBABLE)
            }
        }
        source.lines().forEachIndexed { index, raw ->
            val trimmed = raw.trim()
            val indent = raw.takeWhile { it == ' ' }.length
            if (indent == 0 && trimmed.startsWith("security:")) {
                globalSecurity = trimmed.substringAfter(':').trim() != "[]"
            }
            val method = Regex("^(get|post|put|patch|delete|options|head|trace):$", RegexOption.IGNORE_CASE).find(trimmed)
            if (method != null && indent >= 4) {
                finishOperation(index + 1)
                operation = "${method.value.substringBefore(':').uppercase()} (path declared above)"
                operationIndent = indent
                operationHasSecurity = globalSecurity
            } else if (operation.isNotBlank()) {
                if (indent <= operationIndent && trimmed.endsWith(":")) {
                    finishOperation(index + 1)
                    operation = ""
                } else if (trimmed.startsWith("security:") && indent > operationIndent) operationHasSecurity = trimmed != "security: []"
            }
        }
        if (operation.isNotBlank()) finishOperation(source.lines().size)
        return findings
    }

    private fun finding(
        code: String, path: String, line: Int, title: String, description: String,
        remediation: String, notTested: String, severity: Severity = Severity.MEDIUM,
        status: FindingStatus = FindingStatus.UNVERIFIED, evidence: String = "Schema-level signal only"
    ): Finding = Finding(
        id = "$code-${stable(path, line.toString())}", title = title, severity = severity,
        description = "$description محل: $path:$line", remediation = remediation,
        confidence = if (status == FindingStatus.INFORMATIONAL) "High" else "Low–Medium",
        evidence = EvidenceSanitizer.sanitize(evidence).take(180), cwe = "CWE-862", status = status,
        affectedAsset = path, exactLocation = "$path:$line", detectionMethod = "GraphQL SDL / SOAP WSDL / OpenAPI YAML static parser",
        businessImpact = "در صورت خصوصی بودن operation و نبود کنترل سمت سرور، احتمال افشای داده یا عملیات غیرمجاز وجود دارد.",
        exploitPrerequisites = "نیازمندی auth و رفتار resolver/endpoint از روی schema به‌تنهایی قابل اثبات نیست.",
        safeValidation = "در staging با دو حساب synthetic و داده ساختگی، رفتار مثبت و منفی هر operation را بررسی کنید.",
        notTested = notTested, verificationProcedure = "تست authorization، TLS و policy را در staging اجرا و نتیجه را به همین schema version متصل کنید.",
        expectedResult = "درخواست فاقد مجوز رد شود و transport امن باشد."
    )

    private fun stable(path: String, value: String): String = MessageDigest.getInstance("SHA-256")
        .digest("$path|$value".toByteArray(Charsets.UTF_8)).take(6).joinToString("") { "%02x".format(it) }
}
