package com.siteguard.app.core

/** Shared lifecycle and safe test catalogue for all specialist domains. */
enum class AssessmentDomain { WEB, API, NETWORK, MOBILE, SOURCE, WORDPRESS, CLOUD, IDENTITY, CONTAINER, CI_CD, DEFENSIVE_INTELLIGENCE }
enum class AssessmentExecutionMode { MANUAL, ASSISTED, AUTONOMOUS_SAFE, ISOLATED_LAB }
enum class AssessmentTestState { PROPOSED, EXECUTED, SKIPPED, BLOCKED, FAILED }

data class AssessmentAuthorizationV1(
    val authorizationId: String,
    val owner: String,
    val authorizedAssets: Set<String>,
    val excludedAssets: Set<String> = emptySet(),
    val allowedMethods: Set<String>,
    val validFromEpochMs: Long,
    val validUntilEpochMs: Long,
    val maxRequests: Int,
    val requestsPerMinute: Int,
    val emergencyStop: String
)

data class AssessmentTestDefinition(
    val testId: String,
    val domain: AssessmentDomain,
    val title: String,
    val method: String,
    val destructive: Boolean = false,
    val requiresHumanApproval: Boolean = false,
    val labOnly: Boolean = false
)

data class PlannedAssessmentTest(
    val definition: AssessmentTestDefinition,
    val state: AssessmentTestState,
    val reason: String
)

data class AssessmentPlanV1(
    val authorizationId: String?,
    val mode: AssessmentExecutionMode,
    val generatedAtEpochMs: Long,
    val tests: List<PlannedAssessmentTest>,
    val emergencyStopAvailable: Boolean,
    val coverageDenominator: Int
)

object UniversalAssessmentPlanner {
    val safeCatalog = listOf(
        AssessmentTestDefinition("WEB-HEADERS-001", AssessmentDomain.WEB, "بازبینی passive هدرهای امنیتی", "PASSIVE_HTTP_GET"),
        AssessmentTestDefinition("WEB-TLS-CONFIG-001", AssessmentDomain.WEB, "بازبینی تنظیمات TLS", "READ_ONLY_CONFIG"),
        AssessmentTestDefinition("API-SCHEMA-001", AssessmentDomain.API, "بازبینی schema و permissionهای API از فایل/خروجی", "LOCAL_SCHEMA_REVIEW"),
        AssessmentTestDefinition("NET-CONFIG-001", AssessmentDomain.NETWORK, "بازبینی ایستای پیکربندی شبکه", "LOCAL_CONFIG_REVIEW"),
        AssessmentTestDefinition("NET-TCP-001", AssessmentDomain.NETWORK, "اتصال TCP به IP و پورت دقیق مجاز", "AUTHORIZED_TCP_CONNECT"),
        AssessmentTestDefinition("MOBILE-MANIFEST-001", AssessmentDomain.MOBILE, "بازبینی Manifest و تنظیمات Android", "LOCAL_SOURCE_REVIEW"),
        AssessmentTestDefinition("SOURCE-STATIC-001", AssessmentDomain.SOURCE, "تحلیل ایستای سورس و dependency manifest", "LOCAL_SOURCE_REVIEW"),
        AssessmentTestDefinition("WP-SOURCE-001", AssessmentDomain.WORDPRESS, "بازبینی سورس و پیکربندی WordPress/WooCommerce", "LOCAL_SOURCE_REVIEW"),
        AssessmentTestDefinition("CLOUD-IAC-001", AssessmentDomain.CLOUD, "بازبینی ایستای Infrastructure as Code", "LOCAL_CONFIG_REVIEW"),
        AssessmentTestDefinition("IDENTITY-CONFIG-001", AssessmentDomain.IDENTITY, "بازبینی read-only پیکربندی identity", "READ_ONLY_CONFIG"),
        AssessmentTestDefinition("PURPLE-SYNTHETIC-001", AssessmentDomain.DEFENSIVE_INTELLIGENCE, "اعتبارسنجی detection با event مصنوعی", "SYNTHETIC_EVENT", requiresHumanApproval = true, labOnly = true)
    )

    fun buildPlan(
        mode: AssessmentExecutionMode,
        authorization: AssessmentAuthorizationV1?,
        availableLocalInputs: Set<AssessmentDomain>,
        labIsolated: Boolean = false,
        now: Long = System.currentTimeMillis()
    ): AssessmentPlanV1 {
        val validAuth = authorization?.takeIf {
            now in it.validFromEpochMs..it.validUntilEpochMs && it.authorizationId.isNotBlank() &&
                it.maxRequests > 0 && it.requestsPerMinute > 0 && it.authorizedAssets.isNotEmpty()
        }
        val tests = safeCatalog.map { test ->
            val requiresTargetAuth = test.method in setOf("PASSIVE_HTTP_GET", "AUTHORIZED_TCP_CONNECT")
            val stateReason = when {
                test.destructive -> AssessmentTestState.BLOCKED to "تست مخرب در کاتالوگ خودکار پشتیبانی نمی‌شود."
                test.labOnly && (!labIsolated || mode != AssessmentExecutionMode.ISOLATED_LAB) -> AssessmentTestState.BLOCKED to "فقط در lab ایزوله مجاز است."
                requiresTargetAuth && validAuth == null -> AssessmentTestState.BLOCKED to "مانیفست مجوز معتبر برای تعامل با هدف وجود ندارد."
                test.domain !in availableLocalInputs && !requiresTargetAuth -> AssessmentTestState.SKIPPED to "ورودی محلی/خروجی پیکربندی برای این دامنه ارائه نشده است."
                mode == AssessmentExecutionMode.MANUAL -> AssessmentTestState.PROPOSED to "نیازمند انتخاب و اجرای دستی کاربر است."
                mode == AssessmentExecutionMode.ASSISTED -> AssessmentTestState.PROPOSED to "طرح پیشنهادی است و پیش از اجرا باید تأیید شود."
                test.requiresHumanApproval -> AssessmentTestState.BLOCKED to "تأیید انسانی جداگانه لازم است؛ اجرای خودکار انجام نمی‌شود."
                else -> AssessmentTestState.PROPOSED to "فقط تست allowlist شده و non-destructive؛ هنوز اجرا نشده است."
            }
            PlannedAssessmentTest(test, stateReason.first, stateReason.second)
        }
        return AssessmentPlanV1(validAuth?.authorizationId, mode, now, tests, emergencyStopAvailable = true, coverageDenominator = tests.size)
    }
}

class EmergencyStopController {
    @Volatile private var stopped = false
    fun stop() { stopped = true }
    fun reset() { stopped = false }
    fun isStopped(): Boolean = stopped
    fun requireRunning() { check(!stopped) { "ارزیابی با Emergency Stop متوقف شده است." } }
}


data class SpecialistDomainCoverage(
    val domain: String,
    val state: String,
    val filesExamined: Int,
    val findings: Int,
    val notes: String
)
