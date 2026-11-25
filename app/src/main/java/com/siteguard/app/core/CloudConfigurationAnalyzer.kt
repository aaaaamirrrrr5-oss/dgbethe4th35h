package com.siteguard.app.core

/** Offline, source-only review of Terraform, Docker, Kubernetes and CI/CD configuration. */
object CloudConfigurationAnalyzer {
    fun analyze(files: Map<String, String>): List<Finding> {
        val out = mutableListOf<Finding>()
        files.forEach { (path, text) ->
            val lower = path.lowercase()
            val isDocker = lower.substringAfterLast('/') == "dockerfile" || lower.endsWith(".dockerfile")
            val isK8s = lower.endsWith(".yaml") || lower.endsWith(".yml") || lower.endsWith(".json")
            val isTf = lower.endsWith(".tf") || lower.endsWith(".tfvars")
            val isPolicyJson = lower.endsWith(".json")
            val isWorkflow = lower.contains(".github/workflows/")
            if (!(isDocker || isK8s || isTf || isPolicyJson || isWorkflow)) return@forEach
            val lines = text.lines()
            lines.forEachIndexed { index, raw ->
                val line = raw.trim()
                val n = index + 1
                if (isDocker && Regex("(?i)^USER\\s+root(?:\\s|$)").containsMatchIn(line)) {
                    add(out, "SG-CLD-DOCKER-ROOT", path, n, "Container با کاربر root اجرا می‌شود", Severity.HIGH, "CWE-250", line,
                        "یک کاربر غیر root اختصاصی بسازید و USER غیر root را برای stage نهایی تعیین کنید.", "این بررسی اجرای واقعی image و امکان privilege escalation را آزمایش نمی‌کند.")
                }
                if (isDocker && Regex("(?i)^FROM\\s+\\S+:latest(?:\\s|$)").containsMatchIn(line)) {
                    add(out, "SG-CLD-IMAGE-LATEST", path, n, "Base image با tag شناور latest استفاده شده است", Severity.LOW, "CWE-1104", line,
                        "نسخه یا digest image را pin کنید و به‌روزرسانی‌ها را با فرایند کنترل‌شده انجام دهید.", "محتوای registry، provenance و CVEهای image بررسی نشده‌اند.")
                }
                if (isDocker && Regex("(?i)^ADD\\s+https?://").containsMatchIn(line)) {
                    add(out, "SG-CLD-DOCKER-REMOTE-ADD", path, n, "دریافت مستقیم remote با Docker ADD دیده شد", Severity.MEDIUM, "CWE-494", "ADD remote resource (URL redacted)",
                        "artifact را در pipeline امن دریافت، hash/signature آن را بررسی و با COPY از context کنترل‌شده وارد کنید.", "محتوای remote دریافت یا اجرا نشده است.")
                }
                if (isK8s && Regex("(?i)^privileged:\\s*true\\b").containsMatchIn(line)) {
                    add(out, "SG-CLD-K8S-PRIVILEGED", path, n, "Container در Kubernetes privileged است", Severity.HIGH, "CWE-250", line,
                        "privileged را حذف کنید؛ فقط capabilityهای مشخص و ضروری را اضافه و Pod Security Admission را اعمال کنید.", "دسترسی واقعی node و admission policy cluster مشاهده نشده است.")
                }
                if (isK8s && Regex("(?i)^hostNetwork:\\s*true\\b|^hostPID:\\s*true\\b|^hostIPC:\\s*true\\b").containsMatchIn(line)) {
                    add(out, "SG-CLD-K8S-HOSTNS", path, n, "Pod از namespace شبکه/پردازه میزبان استفاده می‌کند", Severity.HIGH, "CWE-668", line,
                        "host namespace را حذف کنید مگر با نیاز مستند؛ دسترسی و جداسازی node را بازبینی کنید.", "اثر پیکربندی روی cluster فعال ارزیابی نشده است.")
                }
                if (isK8s && Regex("(?i)^hostPath:").containsMatchIn(line)) {
                    add(out, "SG-CLD-K8S-HOSTPATH", path, n, "mount از hostPath تعریف شده است", Severity.MEDIUM, "CWE-668", line,
                        "از volumeهای محدودشده استفاده کنید؛ مسیرهای حساس میزبان و socketهای runtime را mount نکنید.", "مسیر واقعی hostPath و مجوزهای node بررسی نشده‌اند.")
                }
                if (isK8s && Regex("(?i)^runAsUser:\\s*0\\b").containsMatchIn(line)) {
                    add(out, "SG-CLD-K8S-ROOT", path, n, "Pod صریحاً با UID صفر اجرا می‌شود", Severity.HIGH, "CWE-250", line,
                        "runAsNonRoot را فعال و runAsUser غیرصفر اختصاص دهید.", "تصویر runtime و overrideهای policy بررسی نشده‌اند.")
                }
                if (isK8s && Regex("(?i)^readOnlyRootFilesystem:\\s*false\\b").containsMatchIn(line)) {
                    add(out, "SG-CLD-K8S-WRITABLE-ROOT", path, n, "Filesystem ریشه container قابل‌نوشتن است", Severity.LOW, "CWE-732", line,
                        "readOnlyRootFilesystem را فعال کنید و فقط مسیرهای موقت ضروری را به volume محدود منتقل کنید.", "نیازهای نوشتن برنامه و وجود volume جایگزین بررسی نشده است.")
                }
                if ((isTf && Regex("(?i)\\b(actions|Action)\\s*=\\s*\\[?\\s*\"\\*\"").containsMatchIn(line)) ||
                    (isPolicyJson && Regex("(?i)\"Action\"\\s*:\\s*\"\\*\"").containsMatchIn(line))) {
                    add(out, "SG-CLD-IAM-WILDCARD-ACTION", path, n, "IAM policy شامل Action wildcard است", Severity.HIGH, "CWE-732", "Action wildcard (policy value reviewed; raw line omitted)",
                        "Actionها را به حداقل عملیات لازم محدود کنید و منابع را تا حد امکان با ARN/نام دقیق مشخص کنید.", "role trust، شرط‌ها و policy نهایی resolve نشده‌اند.")
                }
                if ((isTf && Regex("(?i)\\b(Resource|resources)\\s*=\\s*\\[?\\s*\"\\*\"").containsMatchIn(line)) ||
                    (isPolicyJson && Regex("(?i)\"Resource\"\\s*:\\s*\"\\*\"").containsMatchIn(line))) {
                    add(out, "SG-CLD-IAM-WILDCARD-RESOURCE", path, n, "IAM policy به همه منابع اعمال می‌شود", Severity.HIGH, "CWE-732", "Resource wildcard (raw policy omitted)",
                        "منابع را به محدوده لازم کاهش دهید و policy را با policy simulator/provider tooling فقط در حالت read-only ارزیابی کنید.", "policyهای ترکیبی و شرایط IAM بررسی نشده‌اند.")
                }
                if (isTf && Regex("(?i)(cidr_blocks|source_ranges)\\s*=\\s*\\[?\\s*\"0\\.0\\.0\\.0/0\"").containsMatchIn(line)) {
                    add(out, "SG-CLD-PUBLIC-INGRESS", path, n, "قانون ingress به IPv4 عمومی باز است", Severity.MEDIUM, "CWE-668", line,
                        "مبدأ را به IP/range موردنیاز محدود کنید؛ دسترسی مدیریت را از VPN/bastion و policyهای کمینه عبور دهید.", "پورت/پروتکل و اتصال واقعی سرویس از همین خط به‌تنهایی معلوم نیست.")
                }
                if (isPolicyJson && Regex("(?i)\"Principal\"\\s*:\\s*\"\\*\"").containsMatchIn(line) &&
                    line.contains("Allow", true) && (text.contains("s3:", true) || text.contains("storage", true))) {
                    add(out, "SG-CLD-PUBLIC-RESOURCE-POLICY", path, n, "سیاست resource شامل Principal عمومی و Allow است", Severity.HIGH, "CWE-732", "Public principal and Allow policy detected; raw statement omitted",
                        "Principal را به حساب/roleهای دقیق محدود و دسترسی anonymous را حذف کنید؛ policy مؤثر و exceptionها را با ابزار رسمی read-only بررسی کنید.", "این parser تمام ترکیب‌های IAM/resource policy را resolve نمی‌کند و دسترسی مؤثر را اثبات نمی‌کند.")
                }
                if ((isK8s || isTf) && Regex("(?i)(publicly_accessible|public_access_block|block_public_acls)\\s*=\\s*false\\b").containsMatchIn(line)) {
                    add(out, "SG-CLD-PUBLIC-STORAGE", path, n, "تنظیم عمومی‌سازی storage نیازمند بازبینی است", Severity.MEDIUM, "CWE-732", line,
                        "دسترسی anonymous/public را غیرفعال کنید مگر با نیاز تجاری مستند؛ کنترل IAM، encryption و logging را نیز بررسی کنید.", "دسترسی effective و policyهای ارث‌بری‌شده بررسی نشده‌اند.")
                }
                if (isWorkflow && Regex("(?i)^pull_request_target:").containsMatchIn(line)) {
                    val context = lines.drop(index).take(80).joinToString("\n")
                    if (context.contains("secrets.", true) || Regex("(?i)permissions:\\s*write-all").containsMatchIn(context)) {
                        add(out, "SG-CLD-CI-PR-TARGET", path, n, "Workflow با pull_request_target و دسترسی حساس نیازمند بازبینی است", Severity.HIGH, "CWE-250", "pull_request_target with sensitive permissions/secrets context",
                            "workflowهای untrusted PR را از secret و token نوشتنی جدا کنید؛ permissionهای GITHUB_TOKEN را حداقلی کنید و کد fork را در context دارای secret اجرا نکنید.", "workflow اجرا نشده و دسترسی مؤثر runner/token بررسی نشده است.")
                    }
                }
                if (isWorkflow && Regex("(?i)^\\s*uses:\\s*[^@]+@v[0-9]+").containsMatchIn(raw)) {
                    add(out, "SG-CLD-CI-ACTION-TAG", path, n, "GitHub Action با tag به‌جای SHA ثابت شده است", Severity.INFO, "CWE-829", "uses: action@vN (repository omitted)",
                        "برای زنجیره تأمین قابل‌بازتولید، action را به full commit SHA pin کنید و فرآیند به‌روزرسانی کنترل‌شده داشته باشید.", "سلامت و provenance action بررسی نشده است.", FindingStatus.INFORMATIONAL)
                }
                if (Regex("(?i)^\\s*(password|client_secret|api_key|access_key|secret_access_key)\\s*[:=]\\s*['\"]?[^$<{][^#]*").containsMatchIn(line) && !line.contains("${'$'}{")) {
                    add(out, "SG-CLD-POSSIBLE-SECRET", path, n, "مقدار شبیه secret در پیکربندی پیدا شد", Severity.HIGH, "CWE-798", "نام فیلد محرمانه شناسایی شد؛ مقدار در شواهد حذف شده است",
                        "مقدار را از سورس حذف کنید، در secret manager نگه دارید و در صورت واقعی بودن آن را rotate کنید.", "مقدار واقعی عمداً در گزارش ذخیره نمی‌شود و اعتبار آن بررسی نشده است.")
                }
            }
        }
        return out.distinctBy { it.id }
    }

    private fun add(out: MutableList<Finding>, id: String, path: String, line: Int, title: String, severity: Severity,
                    cwe: String, evidence: String, remediation: String, notTested: String,
                    status: FindingStatus = FindingStatus.PROBABLE) {
        out += Finding(
            id = "$id-L$line", title = title, severity = severity,
            description = "نشانه پیکربندی در $path:$line مشاهده شد؛ نتیجه، تحلیل ایستای فایل است و وضعیت محیط اجرا را اثبات نمی‌کند.",
            remediation = remediation, confidence = if (status == FindingStatus.INFORMATIONAL) "High" else "Low–Medium",
            evidence = EvidenceSanitizer.sanitize(evidence).take(180), cwe = cwe, status = status,
            affectedAsset = path, exactLocation = "$path:$line", detectionMethod = "Cloud/container/IaC deterministic configuration review",
            businessImpact = "در صورت مؤثر بودن پیکربندی، ممکن است سطح دسترسی یا سطح مواجهه منابع ابری افزایش یابد.",
            exploitPrerequisites = "وضعیت provider، policy inheritance، network path و resource فعال بررسی نشده‌اند.",
            safeValidation = "خروجی plan/describe read-only و policy evaluation را با نقش محدود در محیط غیرتولیدی بررسی کنید.",
            notTested = notTested, verificationProcedure = "پیکربندی اصلاح‌شده را در حساب/lab جدا با تست policy و regression بررسی کنید.",
            expectedResult = "دسترسی حداقلی، اجرای non-root و جداسازی شبکه/فرآیند برقرار باشد."
        )
    }
}
