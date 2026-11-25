plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}
android {
    namespace = "com.siteguard.app"
    compileSdk = 35
    defaultConfig {
        applicationId = "com.siteguard.app"
        minSdk = 26
        targetSdk = 35
        versionCode = 15
        versionName = "0.14.0"
    }
    // Signing is optional and user-controlled: set all four SITEGUARD_* variables (environment or gradle.properties)
    // to produce a signed release APK. Without them, :app:assembleRelease yields an unsigned APK (CI signs it separately).
    val signingStore = (System.getenv("SITEGUARD_KEYSTORE_PATH") ?: (project.findProperty("SITEGUARD_KEYSTORE_PATH") as String?))
    val signingAlias = (System.getenv("SITEGUARD_KEY_ALIAS") ?: (project.findProperty("SITEGUARD_KEY_ALIAS") as String?))
    val signingStorePassword = (System.getenv("SITEGUARD_KEYSTORE_PASSWORD") ?: (project.findProperty("SITEGUARD_KEYSTORE_PASSWORD") as String?))
    val signingKeyPassword = (System.getenv("SITEGUARD_KEY_PASSWORD") ?: (project.findProperty("SITEGUARD_KEY_PASSWORD") as String?))
    val hasSigning = listOf(signingStore, signingAlias, signingStorePassword, signingKeyPassword).all { !it.isNullOrBlank() }
    signingConfigs {
        if (hasSigning) {
            create("release") {
                storeFile = file(signingStore!!)
                storePassword = signingStorePassword
                keyAlias = signingAlias
                keyPassword = signingKeyPassword
            }
        }
    }
    buildTypes {
        release {
            isDebuggable = false
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            if (hasSigning) signingConfig = signingConfigs.getByName("release")
        }
    }
    buildFeatures { compose = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}
dependencies {
    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.activity:activity-compose:1.10.0")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.work:work-runtime-ktx:2.10.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    debugImplementation("androidx.compose.ui:ui-tooling")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
}
