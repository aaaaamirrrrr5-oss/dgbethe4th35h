package com.siteguard.app

import android.graphics.Paint
import android.graphics.Typeface
import android.graphics.pdf.PdfDocument
import android.text.Layout
import android.text.StaticLayout
import android.text.TextPaint
import android.text.TextDirectionHeuristics
import java.io.ByteArrayOutputStream

/** Creates a paginated, RTL-aware PDF from a sanitized Persian report text. */
object PdfReportRenderer {
    fun render(reportText: String): ByteArray {
        require(reportText.isNotBlank()) { "گزارش خالی است." }
        require(reportText.length <= 500_000) { "گزارش برای تولید PDF بیش از حد بزرگ است؛ خروجی JSON را استفاده کنید." }
        val document = PdfDocument()
        val bodyPaint = TextPaint(Paint.ANTI_ALIAS_FLAG).apply {
            color = android.graphics.Color.rgb(28, 31, 38)
            textSize = 10.5f
            typeface = Typeface.create("sans-serif", Typeface.NORMAL)
        }
        val titlePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = android.graphics.Color.rgb(190, 35, 58)
            textSize = 18f
            typeface = Typeface.create("sans-serif", Typeface.BOLD)
        }
        val footerPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = android.graphics.Color.DKGRAY
            textSize = 8f
        }
        val pageWidth = 595
        val pageHeight = 842
        val margin = 42f
        val bodyWidth = (pageWidth - margin * 2).toInt()
        val layout = StaticLayout.Builder.obtain(reportText, 0, reportText.length, bodyPaint, bodyWidth)
            .setAlignment(Layout.Alignment.ALIGN_NORMAL)
            .setTextDirection(TextDirectionHeuristics.RTL)
            .setIncludePad(true)
            .setLineSpacing(2f, 1.08f)
            .build()
        val contentHeight = 710f
        val totalLines = layout.lineCount.coerceAtLeast(1)
        var startLine = 0
        var pageNumber = 1
        try {
            while (startLine < totalLines) {
                val startTop = layout.getLineTop(startLine).toFloat()
                var endLine = startLine + 1
                while (endLine < totalLines && layout.getLineBottom(endLine).toFloat() - startTop <= contentHeight) endLine++
                val info = PdfDocument.PageInfo.Builder(pageWidth, pageHeight, pageNumber).create()
                val page = document.startPage(info)
                val canvas = page.canvas
                canvas.drawColor(android.graphics.Color.WHITE)
                canvas.drawText("SiteGuard Security Assessment", margin, 30f, titlePaint)
                canvas.drawText("نسخه ${com.siteguard.app.core.SiteGuardBuildInfo.VERSION_NAME}", margin, 48f, footerPaint)
                canvas.save()
                canvas.clipRect(margin, 64f, pageWidth - margin, 785f)
                canvas.translate(margin, 64f - startTop)
                layout.draw(canvas)
                canvas.restore()
                canvas.drawText("SiteGuard • گزارش محلی • صفحه $pageNumber", margin, 816f, footerPaint)
                document.finishPage(page)
                startLine = endLine
                pageNumber++
            }
            val output = ByteArrayOutputStream()
            document.writeTo(output)
            return output.toByteArray()
        } finally {
            document.close()
        }
    }
}
