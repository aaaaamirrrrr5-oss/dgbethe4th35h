package com.siteguard.app

import android.content.ClipData
import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import java.io.File

/**
 * Shares text without risking Binder's ~1 MB transaction limit.
 * Small payloads go through EXTRA_TEXT; large reports are written to the app cache and shared as a
 * read-only content:// stream through FileProvider (no storage permission, no public file).
 */
object SafeShare {
    private const val INLINE_LIMIT_CHARS = 100_000
    private const val SHARE_DIR = "shared"
    private const val MAX_SHARE_FILES = 10

    fun shareText(context: Context, mimeType: String, subject: String, text: String, chooserTitle: String, fileName: String) {
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = mimeType
            putExtra(Intent.EXTRA_SUBJECT, subject)
        }
        if (text.length <= INLINE_LIMIT_CHARS) {
            intent.putExtra(Intent.EXTRA_TEXT, text)
        } else {
            val dir = File(context.cacheDir, SHARE_DIR).apply { mkdirs() }
            pruneOldFiles(dir)
            val safeName = fileName.replace(Regex("[^A-Za-z0-9._-]"), "_").ifBlank { "siteguard-report.txt" }
            val file = File(dir, safeName)
            file.writeText(text, Charsets.UTF_8)
            val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
            intent.putExtra(Intent.EXTRA_STREAM, uri)
            intent.clipData = ClipData.newRawUri(safeName, uri)
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        context.startActivity(Intent.createChooser(intent, chooserTitle))
    }

    private fun pruneOldFiles(dir: File) {
        val files = dir.listFiles()?.sortedByDescending { it.lastModified() } ?: return
        files.drop(MAX_SHARE_FILES - 1).forEach { it.delete() }
    }
}
