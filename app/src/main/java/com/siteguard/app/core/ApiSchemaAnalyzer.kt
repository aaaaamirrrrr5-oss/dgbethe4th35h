package com.siteguard.app.core

import org.json.JSONObject

/**
 * Static OpenAPI JSON review. This is schema analysis only: it never sends requests
 * and cannot establish effective authorization at runtime. Public operations may
 * be intentional and therefore produce probable/manual-review findings.
 */
object ApiSchemaAnalyzer {
    private val methods = setOf("get", "put", "post", "delete", "options", "head", "patch", "trace")

    fun analyze(files: Map<String, String>): List<Finding> {
        val findings = mutableListOf<Finding>()
        files.forEach { (path, source) ->
            val lower = path.lowercase()
            if (!lower.endsWith(".json")) return@forEach
            val root = runCatching { JSONObject(source) }.getOrNull() ?: return@forEach
            val openApiVersion = root.optString("openapi")
            val swaggerVersion = root.optString("swagger")
            if (openApiVersion.isBlank() && swaggerVersion.isBlank()) return@forEach

            val globalSecurity = root.optJSONArray("security")
            val paths = root.optJSONObject("paths")
            if (paths != null) {
                val pathIterator = paths.keys()
                while (pathIterator.hasNext()) {
                    val endpoint = pathIterator.next()
                    val pathItem = paths.optJSONObject(endpoint) ?: continue
                    methods.forEach methodLoop@ { method ->
                        val operation = pathItem.optJSONObject(method) ?: return@methodLoop
                        val location = "$.paths[\"$endpoint\"].$method"
                        val operationSecurity = if (operation.has("security")) operation.optJSONArray("security") else globalSecurity
                        if (operationSecurity == null || operationSecurity.length() == 0) {
                            findings += Finding(
                                id = "SG-API-OPENAPI-NO-SECURITY-${stableId(path, endpoint, method)}",
                                title = "برای عملیات API سازوکار امنیتی در OpenAPI تعریف نشده است",
                                severity = Severity.MEDIUM,
                                description = "در $path، عملیات ${method.uppercase()} $endpoint فاقد security مؤثر در سند OpenAPI است. ممکن است endpoint عمداً عمومی باشد؛ این یافته نیازمند بررسی مالک API است.",
                                remediation = "برای endpointهای خصوصی، security scheme مناسب را در سطح global یا operation تعریف کنید و authorization واقعی سمت سرور را برای هر عملیات و هر object/tenant enforce کنید. endpoint عمومی را مستند و با تست منفی/مثبت حفظ کنید.",
                                confidence = "Low–Medium",
                                evidence = "OpenAPI operation without inherited security: ${method.uppercase()} $endpoint",
                                cwe = "CWE-862",
                                status = FindingStatus.PROBABLE,
                                affectedAsset = path,
                                exactLocation = location,
                                detectionMethod = "OpenAPI JSON static schema review",
                                businessImpact = "اگر endpoint به داده یا عملیات خصوصی دسترسی داشته باشد، فقدان کنترل مجوز می‌تواند به افشای داده یا عملیات غیرمجاز منجر شود.",
                                exploitPrerequisites = "نیازمندی احراز هویت/مجوز و رفتار runtime فقط از روی سند قابل اثبات نیست.",
                                safeValidation = "تعریف OpenAPI را با قرارداد API تطبیق دهید و با حساب‌های synthetic و نقش‌های مجاز/غیرمجاز در staging تست کنید.",
                                notTested = "هیچ درخواست شبکه‌ای، تست object-level authorization، tenant isolation، احراز هویت یا business logic اجرا نشده است.",
                                verificationProcedure = "برای هر operation خصوصی، تست بدون token، token با نقش محدود و object متعلق به tenant دیگر را در staging اجرا کنید؛ endpoint عمومی را جداگانه مستند کنید.",
                                expectedResult = "درخواست فاقد مجوز یا خارج از مالکیت رد شود؛ فقط endpointهای مستند عمومی بدون auth باقی بمانند."
                            )
                        }
                        val server = operation.optJSONArray("servers")?.optJSONObject(0)?.optString("url")
                        if (!server.isNullOrBlank() && server.startsWith("http://", true)) {
                            findings += Finding(
                                id = "SG-API-OPENAPI-HTTP-${stableId(path, endpoint, method)}",
                                title = "سرور API در OpenAPI با HTTP تعریف شده است",
                                severity = Severity.LOW,
                                description = "در $path، آدرس سرور برای ${method.uppercase()} $endpoint با HTTP تعریف شده است.",
                                remediation = "در محیط واقعی از HTTPS با TLS معتبر استفاده کنید؛ URLهای HTTP را فقط برای mock/lab محلی و به‌صورت مشخص جدا نگه دارید.",
                                confidence = "Medium",
                                evidence = "Server URL uses http:// (host omitted)",
                                cwe = "CWE-319",
                                status = FindingStatus.PROBABLE,
                                affectedAsset = path,
                                exactLocation = "$location.servers[0].url",
                                detectionMethod = "OpenAPI JSON static schema review",
                                notTested = "TLS endpoint واقعی یا deployment environment بررسی نشده است."
                            )
                        }
                    }
                }
            }
        }
        return findings.distinctBy { it.id }
    }

    private fun stableId(file: String, endpoint: String, method: String): String =
        java.security.MessageDigest.getInstance("SHA-256")
            .digest("$file|$endpoint|$method".toByteArray(Charsets.UTF_8))
            .take(6).joinToString("") { "%02x".format(it) }
}
