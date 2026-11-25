package com.siteguard.app.advanced

import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.util.UUID

/** Transactional patching only inside an explicit app-managed workspace. No remote/production writes. */
data class LocalPatchPreviewV1(val beforeSha256: String, val afterSha256: String, val occurrences: Int, val patchText: String, val patchedContent: String)
data class LocalPatchReceiptV1(val transactionId: String, val target: String, val backup: String, val beforeSha256: String, val afterSha256: String, val appliedAtEpochMs: Long)

class LocalPatchTransactionV1(private val workspaceRoot: File, private val backupRoot: File) {
    init {
        workspaceRoot.mkdirs(); backupRoot.mkdirs()
        require(workspaceRoot.canonicalFile != backupRoot.canonicalFile) { "Workspace and backup directories must be different" }
    }

    fun preview(original: String, exactNeedle: String, replacement: String): LocalPatchPreviewV1 {
        require(original.length <= 2_000_000 && exactNeedle.length <= 100_000 && replacement.length <= 100_000)
        require(exactNeedle.isNotEmpty()) { "Patch target cannot be empty" }
        val count = occurrences(original, exactNeedle)
        require(count == 1) { "Patch requires exactly one unique match; found $count" }
        val patched = original.replaceFirst(exactNeedle, replacement)
        return LocalPatchPreviewV1(sha256(original), sha256(patched), count,
            "--- original\n+++ patched\n- ${exactNeedle.take(500)}\n+ ${replacement.take(500)}", patched)
    }

    fun apply(relativePath: String, expectedBeforeSha256: String, preview: LocalPatchPreviewV1): LocalPatchReceiptV1 {
        val target = resolveInside(workspaceRoot, relativePath)
        require(target.isFile && !Files.isSymbolicLink(target.toPath())) { "Target must be an existing regular non-symlink file" }
        val rawBytes = target.readBytes()
        val current = String(rawBytes, Charsets.UTF_8)
        // A non-UTF-8 (binary/legacy-encoded) file would be silently rewritten with U+FFFD; refuse instead of corrupting it.
        require(current.toByteArray(Charsets.UTF_8).contentEquals(rawBytes)) { "Target is not valid UTF-8 text; refusing to patch to avoid corruption" }
        require(sha256(current) == expectedBeforeSha256 && expectedBeforeSha256 == preview.beforeSha256) { "File changed after preview; rebuild the patch preview" }
        require(sha256(preview.patchedContent) == preview.afterSha256) { "Patch preview hash mismatch" }
        val id = UUID.randomUUID().toString()
        val backup = File(backupRoot.canonicalFile, "$id.backup")
        writeAtomic(backup, current.toByteArray(Charsets.UTF_8))
        val temp = File(target.parentFile, target.name + ".$id.tmp")
        try {
            writeAtomic(temp, preview.patchedContent.toByteArray(Charsets.UTF_8))
            require(sha256(temp.readText(Charsets.UTF_8)) == preview.afterSha256) { "Staged patch integrity check failed" }
            if (target.canExecute()) temp.setExecutable(true, false)
            Files.move(temp.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } catch (e: Exception) {
            temp.delete()
            backup.delete() // no patch was applied, so the unused backup is not left behind
            throw e
        }
        return LocalPatchReceiptV1(id, target.relativeTo(workspaceRoot.canonicalFile).invariantSeparatorsPath,
            backup.canonicalPath, preview.beforeSha256, preview.afterSha256, System.currentTimeMillis())
    }

    fun rollback(receipt: LocalPatchReceiptV1): Boolean {
        val target = resolveInside(workspaceRoot, receipt.target)
        val backup = File(receipt.backup).canonicalFile
        require(backup.parentFile == backupRoot.canonicalFile && backup.isFile && !Files.isSymbolicLink(backup.toPath())) { "Rollback backup is missing or outside backup directory" }
        require(target.isFile && !Files.isSymbolicLink(target.toPath()))
        require(sha256(target.readText(Charsets.UTF_8)) == receipt.afterSha256) { "Target changed since patch; refusing destructive rollback" }
        val original = backup.readText(Charsets.UTF_8)
        require(sha256(original) == receipt.beforeSha256) { "Backup integrity check failed" }
        val temp = File(target.parentFile, target.name + ".rollback-${receipt.transactionId}.tmp")
        writeAtomic(temp, original.toByteArray(Charsets.UTF_8))
        Files.move(temp.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        return sha256(target.readText(Charsets.UTF_8)) == receipt.beforeSha256
    }

    private fun resolveInside(root: File, relative: String): File {
        require(relative.isNotBlank() && !relative.startsWith('/') && !relative.contains('\\') && relative.split('/').none { it == ".." || it.isBlank() })
        val rootCanonical = root.canonicalFile
        var current = rootCanonical
        relative.split('/').forEach { part ->
            current = File(current, part)
            require(!Files.isSymbolicLink(current.toPath())) { "Symlink path is not allowed" }
        }
        val result = current.canonicalFile
        require(result.toPath().startsWith(rootCanonical.toPath())) { "Path escapes workspace" }
        return result
    }

    private fun writeAtomic(file: File, bytes: ByteArray) {
        file.parentFile?.mkdirs()
        val temp = File(file.parentFile, file.name + ".write-tmp")
        temp.outputStream().use { it.write(bytes); it.flush() }
        try { Files.move(temp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE) }
        catch (ignored: Exception) { Files.move(temp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING) }
    }

    private fun occurrences(text: String, needle: String): Int {
        var count = 0; var at = 0
        while (true) { val found = text.indexOf(needle, at); if (found < 0) break; count++; at = found + needle.length }
        return count
    }
    private fun sha256(text: String) = MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
}
