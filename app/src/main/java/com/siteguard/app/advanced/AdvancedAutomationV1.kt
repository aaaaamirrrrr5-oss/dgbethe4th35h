package com.siteguard.app.advanced

/** Supported job types and fail-closed scheduling policy for multi-module automation. */
enum class AutomationKindV1 { PASSIVE_WEB, DNS_POSTURE, THREAT_INTEL_REFRESH, WORDPRESS_READ_ONLY, SOURCE_ARCHIVE, APK_ARCHIVE, CLOUD_CONFIG }
enum class AutomationTriggerV1 { ON_DEMAND, DAILY, WEEKLY }

data class AutomationDefinitionV1(
    val kind: AutomationKindV1,
    val trigger: AutomationTriggerV1,
    val target: String = "",
    val authorizationConfirmed: Boolean,
    val credentialPersisted: Boolean = false,
    val contentUriPersisted: Boolean = false
)

data class AutomationPolicyDecisionV1(val allowed: Boolean, val reason: String)

object AdvancedAutomationPolicyV1 {
    fun validate(definition: AutomationDefinitionV1): AutomationPolicyDecisionV1 {
        if (definition.kind == AutomationKindV1.THREAT_INTEL_REFRESH) {
            return AutomationPolicyDecisionV1(true, "منبع عمومی ثابت CISA؛ فقط GET، بدون credential و بدون هدف شخصی.")
        }
        if (!definition.authorizationConfirmed) return AutomationPolicyDecisionV1(false, "برای زمان‌بندی هدف، تأیید مالکیت/مجوز لازم است.")
        if (definition.kind == AutomationKindV1.WORDPRESS_READ_ONLY && definition.credentialPersisted) {
            return AutomationPolicyDecisionV1(false, "ذخیره گذرواژه وردپرس برای زمان‌بندی غیرفعال است؛ احراز هویت فقط تعاملی انجام شود.")
        }
        if (definition.kind in setOf(AutomationKindV1.SOURCE_ARCHIVE, AutomationKindV1.APK_ARCHIVE, AutomationKindV1.CLOUD_CONFIG) && !definition.contentUriPersisted) {
            return AutomationPolicyDecisionV1(false, "برای اجرای خودکار فایل محلی، دسترسی URI باید به‌صورت پایدار و مجاز برقرار باشد؛ در غیر این صورت فقط اجرای دستی.")
        }
        if (definition.target.isBlank() && definition.kind != AutomationKindV1.THREAT_INTEL_REFRESH) {
            return AutomationPolicyDecisionV1(false, "هدف مشخص نیست.")
        }
        if (definition.kind == AutomationKindV1.WORDPRESS_READ_ONLY) {
            return AutomationPolicyDecisionV1(false, "زمان‌بندی WordPress تا طراحی storage امن credential و تمدید مجوز غیرفعال است.")
        }
        return AutomationPolicyDecisionV1(true, "کار می‌تواند با سیاست محدود و بازبینی مجوز اجرا شود.")
    }
}
