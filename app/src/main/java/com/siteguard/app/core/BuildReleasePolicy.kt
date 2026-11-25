package com.siteguard.app.core


data class AndroidReleaseSnapshotV1(
    val applicationId: String,
    val versionName: String,
    val compileSdk: Int,
    val targetSdk: Int,
    val minSdk: Int,
    val allowBackup: Boolean,
    val exportedActivities: Map<String, Boolean>,
    val dependenciesPinnedOrBomManaged: Boolean,
    val signingConfiguredFromExternalSecrets: Boolean,
    val gradleWrapperPresent: Boolean,
    val optionalLinuxWorker: Boolean = false
)

data class ReleasePreflightResultV1(val readyForDebugBuild: Boolean, val readyForSignedRelease: Boolean, val checks: List<Pair<String, Boolean>>, val blockers: List<String>)

object BuildReleasePolicyV1 {
    private val forbiddenHostedAiHosts = listOf(
        listOf("api", "openai", "com").joinToString("."),
        listOf("api", "anthropic", "com").joinToString("."),
        listOf("generativelanguage", "googleapis", "com").joinToString("."),
        listOf("api", "gemini", "google", "com").joinToString(".")
    )

    /** Inspect application source/config only; documentation references do not count as runtime dependencies. */
    fun scanForHostedInferenceEndpoints(applicationSource: List<String>): List<String> {
        val joined = applicationSource.joinToString("\n").lowercase()
        return forbiddenHostedAiHosts.filter { it in joined }
    }

    fun preflight(snapshot: AndroidReleaseSnapshotV1, applicationSource: List<String>): ReleasePreflightResultV1 {
        val hosted = scanForHostedInferenceEndpoints(applicationSource)
        val checks = listOf(
            "Application ID" to snapshot.applicationId.matches(Regex("^[a-zA-Z][a-zA-Z0-9_]*(\\.[a-zA-Z][a-zA-Z0-9_]*)+$")),
            "Version" to snapshot.versionName.isNotBlank(),
            "SDK levels" to (snapshot.minSdk >= 23 && snapshot.targetSdk >= snapshot.minSdk && snapshot.compileSdk >= snapshot.targetSdk),
            "Backup disabled" to !snapshot.allowBackup,
            "Dependencies pinned/BOM managed" to snapshot.dependenciesPinnedOrBomManaged,
            "No hosted AI inference endpoints" to hosted.isEmpty(),
            "No non-launcher exported activity" to snapshot.exportedActivities.all { (name, exported) -> !exported || name.endsWith("MainActivity") },
            "Gradle wrapper" to snapshot.gradleWrapperPresent
        )
        val blockers = checks.filterNot { it.second }.map { "${it.first} validation failed" } + hosted.map { "اجبار cloud inference شناسایی شد: $it" }
        val debugReady = checks.filter { it.first != "Gradle wrapper" }.all { it.second }
        val signedReady = debugReady && snapshot.signingConfiguredFromExternalSecrets
        return ReleasePreflightResultV1(debugReady, signedReady, checks, blockers + if (!snapshot.signingConfiguredFromExternalSecrets) listOf("کلید امضا باید خارج از repository و از secretهای CI تأمین شود.") else emptyList())
    }

    fun verifySha256(expected: String, actual: String): Boolean =
        expected.matches(Regex("(?i)^[a-f0-9]{64}$")) && actual.matches(Regex("(?i)^[a-f0-9]{64}$")) && expected.equals(actual, true)
}
