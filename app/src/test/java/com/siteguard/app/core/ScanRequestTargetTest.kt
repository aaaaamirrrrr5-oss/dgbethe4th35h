package com.siteguard.app.core

import org.junit.Assert.assertEquals
import org.junit.Test

class ScanRequestTargetTest {
    @Test fun asciiTargetsAreUnchanged() {
        assertEquals("/", ScanEngine.asciiRequestTarget("/"))
        assertEquals("/a/b?x=1&y=%20z", ScanEngine.asciiRequestTarget("/a/b?x=1&y=%20z"))
    }

    @Test fun nonAsciiPathAndQueryArePercentEncodedAsUtf8() {
        assertEquals("/caf%C3%A9", ScanEngine.asciiRequestTarget("/caf\u00e9"))
        assertEquals("/p?q=%D8%B3", ScanEngine.asciiRequestTarget("/p?q=\u0633"))
        assertEquals("/%F0%9F%98%80", ScanEngine.asciiRequestTarget("/\uD83D\uDE00"))
    }

    @Test fun idnHostCanonicalFormIsAsciiForDnsAndHostHeader() {
        assertEquals("xn--exmple-cua.com", canonicalHost("Ex\u00e4mple.com"))
    }
}
