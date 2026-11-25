package com.siteguard.app.advanced

/** Static IaC/network configuration checks. Runtime cloud APIs are intentionally not invoked. */
data class CloudNetworkFindingV1(val id: String, val severity: String, val line: Int, val title: String, val evidence: String, val remediation: String)
data class CloudNetworkReportV1(val fileName: String, val platform: String, val findings: List<CloudNetworkFindingV1>, val limitations: List<String>)

object CloudNetworkPostureAnalyzerV1 {
    fun analyze(fileName: String, content: String): CloudNetworkReportV1 {
        require(content.length <= 2_000_000) { "Configuration file exceeds 2 MB" }
        val lower = fileName.lowercase()
        val platform = when {
            "terraform" in lower || lower.endsWith(".tf") -> "Terraform"
            lower.endsWith(".yaml") || lower.endsWith(".yml") -> "Kubernetes/Cloud YAML"
            "dockerfile" in lower -> "Docker"
            lower.endsWith(".json") -> "Cloud/JSON"
            else -> "Generic infrastructure configuration"
        }
        val findings = mutableListOf<CloudNetworkFindingV1>()
        content.lineSequence().forEachIndexed { index, raw ->
            val line = raw.trim(); val n = index + 1
            if (line.isBlank() || line.startsWith("#") || line.startsWith("//")) return@forEachIndexed
            fun add(id: String, severity: String, title: String, evidence: String, fix: String) {
                findings += CloudNetworkFindingV1(id, severity, n, title, evidence.take(160), fix)
            }
            if (Regex("(?i)privileged\\s*:\\s*true").containsMatchIn(line)) add("CLOUD-K8S-PRIVILEGED", "HIGH", "کانتینر privileged پیکربندی شده است", line, "privileged را حذف و فقط capabilityهای ضروری را اضافه کنید.")
            if (Regex("(?i)hostNetwork\\s*:\\s*true").containsMatchIn(line)) add("CLOUD-K8S-HOST-NETWORK", "MEDIUM", "Pod از hostNetwork استفاده می‌کند", line, "شبکه اختصاصی و NetworkPolicy محدود را ترجیح دهید.")
            if (Regex("(?i)runAsUser\\s*:\\s*0|runAsNonRoot\\s*:\\s*false").containsMatchIn(line)) add("CLOUD-K8S-ROOT", "MEDIUM", "اجرای workload با root یا امکان root دیده شد", line, "runAsNonRoot را فعال و UID غیرصفر تنظیم کنید.")
            if (Regex("(?i)0\\.0\\.0\\.0/0").containsMatchIn(line)) add("CLOUD-WIDE-INGRESS", "HIGH", "قانون شبکه دسترسی همه IPv4ها را می‌پذیرد", line, "CIDR را به IPها و subnetهای موردنیاز محدود کنید و پورت‌های مدیریتی را عمومی نکنید.")
            if (Regex("(?i)publicly_accessible\\s*=\\s*true|acl\\s*=\\s*\"public-read\"|block_public_(acls|policy)\\s*=\\s*false").containsMatchIn(line)) add("CLOUD-PUBLIC-STORAGE", "HIGH", "نشانه‌ای از Storage عمومی مشاهده شد", line, "دسترسی عمومی را ببندید و bucket policy و inherited ACL را جداگانه بازبینی کنید.")
            if (Regex("(?i)privileged: true|allowPrivilegeEscalation:\\s*true").containsMatchIn(line)) add("CLOUD-PRIV-ESCALATION", "HIGH", "امکان افزایش privilege در workload دیده شد", line, "allowPrivilegeEscalation را false کنید مگر با استثنای مستند و محدود.")
            if (Regex("(?i)image:\\s*[^\\s]+:latest\\b").containsMatchIn(line) || Regex("(?i)FROM\\s+[^\\s]+:latest\\b").containsMatchIn(line)) add("CLOUD-UNPINNED-IMAGE", "LOW", "تصویر کانتینر با tag متغیر latest تعریف شده است", line, "از نسخه یا digest ثابت استفاده و فرآیند به‌روزرسانی کنترل‌شده تعریف کنید.")
            if (Regex("(?i)minimum_tls_version\\s*=\\s*\"TLS1_[01]\"|ssl_protocols\\s+.*TLSv1(?:\\s|;)|ssl_protocols\\s+.*TLSv1\\.1").containsMatchIn(line)) add("CLOUD-LEGACY-TLS", "MEDIUM", "نسخه قدیمی TLS در تنظیمات دیده شد", line, "TLS 1.2 یا 1.3 را با توجه به سازگاری فعال کنید و نسخه‌های قدیمی را حذف کنید.")
            if (Regex("(?i)actions/[^@\\s]+@v[0-9]+(?:\\s|$)").containsMatchIn(line)) add("CLOUD-CI-UNPINNED-ACTION", "INFO", "GitHub Action به tag متغیر pin شده است", line, "Action را به full commit SHA pin و به‌روزرسانی را بازبینی کنید.")
            if (Regex("(?i)effect\\s*[:=]\\s*['\"]?Allow['\"]?").containsMatchIn(line) && Regex("(?i)Action\\s*[:=]\\s*['\"]?\\*['\"]?").containsMatchIn(line)) add("CLOUD-IAM-WILDCARD", "HIGH", "Policy دارای Allow با Action wildcard است", line, "Action و Resource را به حداقل لازم محدود و policy inheritance را ارزیابی کنید.")
        }
        // Basic multi-line IAM policy check: only associate an Allow effect and Action:* within a small local window.
        val lines = content.lines()
        lines.forEachIndexed { index, raw ->
            if (!Regex("(?i)effect\\s*[:=]\\s*['\"]?Allow['\"]?").containsMatchIn(raw)) return@forEachIndexed
            val start = (index - 8).coerceAtLeast(0)
            val stop = (index + 8).coerceAtMost(lines.lastIndex)
            val localBlock = lines.subList(start, stop + 1).joinToString("\n")
            val inlineWildcard = Regex("(?i)Action\\s*[:=]\\s*['\"]?\\*['\"]?").containsMatchIn(localBlock)
            val yamlListWildcard = Regex("(?is)Action\\s*:\\s*\\n(?:[ \\t]*-[ \\t]*['\"]?\\*['\"]?\\s*\\n?){1,4}").containsMatchIn(localBlock)
            if (inlineWildcard || yamlListWildcard) {
                findings += CloudNetworkFindingV1("CLOUD-IAM-WILDCARD", "HIGH", index + 1,
                    "Policy block contains Allow with Action wildcard", raw.trim().take(160),
                    "Action and Resource را به حداقل لازم محدود و policy inheritance را ارزیابی کنید.")
            }
        }
        return CloudNetworkReportV1(fileName.take(240), platform, findings.distinctBy { "${it.id}:${it.line}" }, listOf(
            "این ماژول فایل پیکربندی را به‌صورت ایستا تحلیل می‌کند؛ state واقعی cloud account یا policy مؤثر را نمی‌خواند.",
            "متغیرها، template rendering، inheritance، admission policy و کنترل‌های provider ممکن است نتیجه را تغییر دهند.",
            "هیچ اسکن شبکه، API ابری، credential، exploit یا تغییر پیکربندی اجرا نشده است."
        ))
    }
}
