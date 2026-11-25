package com.siteguard.app.core

/** Single source of truth for user-agent and report provenance metadata. */
object SiteGuardBuildInfo {
    const val VERSION_NAME = "0.14.0"
    const val VERSION_CODE = 15
    const val REPORT_SCHEMA_VERSION = 8
    const val USER_AGENT = "SiteGuard-Android/$VERSION_NAME (authorized-defensive-assessment)"
}
