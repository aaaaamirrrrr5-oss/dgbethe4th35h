package com.siteguard.app.core


enum class SpecificationImplementationStatus { TESTED, IMPLEMENTED, PARTIALLY_SUPPORTED, PLANNED, UNSUPPORTED, BLOCKED }

data class SpecificationExecutionRecordV1(
    val number: Int,
    val filename: String,
    val status: SpecificationImplementationStatus,
    val changedFiles: List<String>,
    val testReferences: List<String>,
    val limitations: List<String>
)

data class ExecutionOrderValidationV1(val valid: Boolean, val errors: List<String>, val nextExpectedNumber: Int)

object SequentialSpecificationLedgerV1 {
    fun validate(records: List<SpecificationExecutionRecordV1>, expectedLast: Int = 23): ExecutionOrderValidationV1 {
        val errors = mutableListOf<String>()
        if (expectedLast < 0 || expectedLast > 99) errors += "شماره انتهایی نامعتبر است."
        if (records.map { it.number } != records.map { it.number }.sorted()) errors += "اسناد به ترتیب عددی اجرا نشده‌اند."
        if (records.map { it.number }.distinct().size != records.size) errors += "شماره سند تکراری وجود دارد."
        val expected = (0..expectedLast).toList()
        val actual = records.map { it.number }
        val missing = expected - actual.toSet()
        if (missing.isNotEmpty()) errors += "اسناد از دست‌رفته: ${missing.joinToString(", ")}."
        records.forEach { record ->
            if (record.filename.isBlank()) errors += "نام فایل سند ${record.number} خالی است."
            if (record.status == SpecificationImplementationStatus.TESTED && record.testReferences.isEmpty()) {
                errors += "سند ${record.number} به عنوان TESTED ثبت شده اما test reference ندارد."
            }
            if (record.status in setOf(SpecificationImplementationStatus.PARTIALLY_SUPPORTED, SpecificationImplementationStatus.PLANNED, SpecificationImplementationStatus.UNSUPPORTED, SpecificationImplementationStatus.BLOCKED) && record.limitations.isEmpty()) {
                errors += "سند ${record.number} محدودیت/دلیل وضعیت ندارد."
            }
        }
        return ExecutionOrderValidationV1(errors.isEmpty(), errors, (actual.lastOrNull() ?: -1) + 1)
    }
}
