package com.siteguard.app

import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.siteguard.app.core.LocalAssessmentArchive
import com.siteguard.app.core.LocalAuditHistory
import com.siteguard.app.core.PersistentAssessmentQueueV1
import com.siteguard.app.core.ScanEngine
import com.siteguard.app.core.ScheduledAssessmentV1
import com.siteguard.app.core.ScheduledAssessmentStatus
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import java.util.concurrent.TimeUnit

/** WorkManager adapter. WorkManager timing is best-effort and OS-managed, not exact. */
object AssessmentQueueWorkSchedulerV1 {
    const val WORK_TAG = "siteguard-authorized-assessment"

    fun enqueue(context: Context, task: ScheduledAssessmentV1) {
        val delayMs = (task.scheduledAtEpochMs - System.currentTimeMillis()).coerceAtLeast(0L)
        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .build()
        val request = OneTimeWorkRequestBuilder<SiteGuardAssessmentWorkerV1>()
            .setInitialDelay(delayMs, TimeUnit.MILLISECONDS)
            .setConstraints(constraints)
            .addTag(WORK_TAG)
            .build()
        val uniqueName = "siteguard-assessment-${task.id}-${task.retryCount}"
        WorkManager.getInstance(context.applicationContext)
            .enqueueUniqueWork(uniqueName, ExistingWorkPolicy.REPLACE, request)
    }

    fun cancelAll(context: Context) {
        WorkManager.getInstance(context.applicationContext).cancelAllWorkByTag(WORK_TAG)
    }
}

/** Executes only the already-authorized passive HTTP GET task from the encrypted queue. */
class SiteGuardAssessmentWorkerV1(
    appContext: Context,
    params: WorkerParameters
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        com.siteguard.app.core.AuthorizationBudget.attachStore(com.siteguard.app.core.SharedPrefsAuthorizationBudgetStore(applicationContext))
        val queue = PersistentAssessmentQueueV1.get(applicationContext)
        return try {
            while (!isStopped) {
                val task = withContext(Dispatchers.IO) { queue.claimDue().firstOrNull() }
                if (task == null) {
                    val now = System.currentTimeMillis()
                    val anotherDueTaskIsWaiting = withContext(Dispatchers.IO) {
                        queue.snapshot().tasks.any {
                            it.status == ScheduledAssessmentStatus.QUEUED && it.scheduledAtEpochMs <= now
                        }
                    }
                    // Another worker may currently hold the single scheduler slot. Retry later
                    // rather than silently dropping a due task from the persistent queue.
                    return if (anotherDueTaskIsWaiting) Result.retry() else Result.success()
                }
                try {
                    val scan = withContext(Dispatchers.IO) {
                        ScanEngine().scan(task.targetUrl, task.authorization.allowPrivateNetwork, task.authorization)
                    }
                    val success = scan.httpStatus != null
                    withContext(Dispatchers.IO) {
                        queue.complete(task.id, success, scan.message)
                        if (success) {
                            runCatching { LocalAuditHistory.get(applicationContext).add(scan, task.authorization) }
                            runCatching {
                                LocalAssessmentArchive.get(applicationContext).add(
                                    "website", scan.host, scan.connectedAddress, scan.findings.size,
                                    com.siteguard.app.core.JsonReportExporter.exportScan(scan)
                                )
                            }
                        } else {
                            retryIfAllowed(queue, task)
                        }
                    }
                } catch (timeout: kotlinx.coroutines.TimeoutCancellationException) {
                    // ScanEngine's own deadline is a CancellationException subclass, but it is an ordinary task failure,
                    // not a worker stop: record it, re-queue within the retry budget and keep draining the queue
                    // instead of rethrowing (which would abort this worker run and strand other due tasks).
                    withContext(NonCancellable + Dispatchers.IO) {
                        runCatching { queue.complete(task.id, false, "مهلت کلی اسکن به پایان رسید.") }
                        retryIfAllowed(queue, task)
                    }
                } catch (cancelled: CancellationException) {
                    withContext(NonCancellable + Dispatchers.IO) {
                        runCatching { queue.complete(task.id, false, "اجرای پس‌زمینه با درخواست توقف لغو شد.") }
                        // The OS interrupted this run (constraints lost, timeout, process pressure); that is not a real
                        // scan failure, so re-queue within the retry budget instead of silently dropping the task.
                        // Skipped when the user pressed Emergency Stop. A user-cancelled task is already CANCELLED,
                        // so complete()/retry() reject it and nothing is re-queued.
                        if (!queue.snapshot().emergencyStopped) retryIfAllowed(queue, task)
                    }
                    throw cancelled
                } catch (error: Exception) {
                    withContext(Dispatchers.IO) {
                        runCatching { queue.complete(task.id, false, error.message ?: "خطای اجرای بررسی") }
                        retryIfAllowed(queue, task)
                    }
                }
            }
            Result.success()
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (ignored: Exception) {
            Result.retry()
        }
    }

    private fun retryIfAllowed(queue: PersistentAssessmentQueueV1, task: ScheduledAssessmentV1) {
        if (task.retryCount >= task.maxRetries) return
        runCatching {
            val next = System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(5)
            val retry = queue.retry(task.id, next)
            if (retry.status == ScheduledAssessmentStatus.QUEUED) {
                AssessmentQueueWorkSchedulerV1.enqueue(applicationContext, retry)
            }
        }
    }
}
