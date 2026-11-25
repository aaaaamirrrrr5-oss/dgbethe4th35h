package com.siteguard.app.core

import android.app.ActivityManager
import android.content.Context
import android.os.Build
import android.os.StatFs
import android.os.PowerManager

 data class DeviceCapabilities(
    val apiLevel: Int,
    val supportedAbis: List<String>,
    val availableMemoryMb: Long,
    val totalMemoryMb: Long,
    val availableStorageMb: Long,
    val thermalStatus: Int?,
    val canRunLightweightAudit: Boolean,
    val canRunProjectAudit: Boolean,
    val warnings: List<String>
)

object DeviceCapabilityDetector {
    fun inspect(context: Context): DeviceCapabilities {
        val activityManager = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val memory = ActivityManager.MemoryInfo().also(activityManager::getMemoryInfo)
        val storage = StatFs(context.filesDir.absolutePath)
        val freeBytes = storage.availableBytes
        val availableMemory = memory.availMem / (1024 * 1024)
        val totalMemory = memory.totalMem / (1024 * 1024)
        val storageMb = freeBytes / (1024 * 1024)
        val thermal = if (Build.VERSION.SDK_INT >= 29) {
            (context.getSystemService(Context.POWER_SERVICE) as PowerManager).currentThermalStatus
        } else null
        val warnings = buildList {
            if (availableMemory < 160) add("RAM آزاد کمتر از ۱۶۰ مگابایت است؛ اسکن پروژه بزرگ محدود شود.")
            if (storageMb < 100) add("فضای آزاد کمتر از ۱۰۰ مگابایت است.")
            if (thermal != null && thermal >= PowerManager.THERMAL_STATUS_SEVERE) add("دمای دستگاه بالاست؛ کار سنگین شروع نشود.")
        }
        val canRun = availableMemory >= 48 && storageMb >= 20 &&
            (thermal == null || thermal < PowerManager.THERMAL_STATUS_CRITICAL)
        val canRunProject = availableMemory >= 192 && storageMb >= 80 &&
            (thermal == null || thermal < PowerManager.THERMAL_STATUS_SEVERE)
        return DeviceCapabilities(
            apiLevel = Build.VERSION.SDK_INT,
            supportedAbis = Build.SUPPORTED_ABIS.toList(),
            availableMemoryMb = availableMemory,
            totalMemoryMb = totalMemory,
            availableStorageMb = storageMb,
            thermalStatus = thermal,
            canRunLightweightAudit = canRun,
            canRunProjectAudit = canRunProject,
            warnings = warnings
        )
    }
}
