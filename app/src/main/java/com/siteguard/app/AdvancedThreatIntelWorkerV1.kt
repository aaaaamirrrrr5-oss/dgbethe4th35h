package com.siteguard.app

import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.siteguard.app.advanced.CisaKevFeedUpdaterV1
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.TimeUnit

object AdvancedThreatIntelSchedulerV1 {
    const val UNIQUE_WORK = "siteguard-cisa-kev-refresh-v1"
    fun scheduleDaily(context: Context) {
        val request = PeriodicWorkRequestBuilder<CisaKevRefreshWorkerV1>(24, TimeUnit.HOURS, 2, TimeUnit.HOURS)
            .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
            .addTag(UNIQUE_WORK)
            .build()
        WorkManager.getInstance(context.applicationContext)
            .enqueueUniquePeriodicWork(UNIQUE_WORK, ExistingPeriodicWorkPolicy.UPDATE, request)
    }
    fun cancel(context: Context) {
        WorkManager.getInstance(context.applicationContext).cancelUniqueWork(UNIQUE_WORK)
    }
}

/** Public feed refresh only; no target site credentials or user data are used. */
class CisaKevRefreshWorkerV1(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result = try {
        val snapshot = withContext(Dispatchers.IO) {
            CisaKevFeedUpdaterV1().updateCache(applicationContext.filesDir.resolve("threat-intel/cisa-kev-v1.json"))
        }
        applicationContext.getSharedPreferences("siteguard_threat_intel", Context.MODE_PRIVATE).edit()
            .putString("last_catalog_version", snapshot.catalogVersion)
            .putString("last_release_date", snapshot.dateReleased)
            .putInt("last_entry_count", snapshot.count)
            .putLong("last_fetch_ms", snapshot.fetchedAtEpochMs)
            .putString("last_sha256", snapshot.sha256)
            .putString("last_status", "success")
            .apply()
        Result.success()
    } catch (cancelled: kotlinx.coroutines.CancellationException) {
        throw cancelled
    } catch (e: Exception) {
        applicationContext.getSharedPreferences("siteguard_threat_intel", Context.MODE_PRIVATE).edit()
            .putString("last_status", "failed")
            .putString("last_error", (e.message ?: e.javaClass.simpleName).take(180))
            .apply()
        Result.retry()
    }
}
