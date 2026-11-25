# SiteGuard release shrinking rules.
# Keep readable crash traces; the mapping file must be archived with every release.
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
# Compose, coroutines and AndroidX ship their own consumer rules. The app itself uses no reflection/serialization
# libraries (org.json is the platform implementation), so no further -keep rules are required today.
# If a Gradle release build later fails or crashes in R8, add the narrowest -keep for the reported class only.

# WorkManager instantiates this worker by class name from its persisted WorkSpec.
-keep class com.siteguard.app.SiteGuardAssessmentWorkerV1 {
    public <init>(android.content.Context, androidx.work.WorkerParameters);
}

# Periodic public CISA KEV refresh worker instantiated by WorkManager from persisted work.
-keep class com.siteguard.app.CisaKevRefreshWorkerV1 {
    public <init>(android.content.Context, androidx.work.WorkerParameters);
}

# Extra obfuscation: flatten package structure and let R8 widen access for better inlining.
-repackageclasses 'sg'
-allowaccessmodification
