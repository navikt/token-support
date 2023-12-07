package no.nav.security.token.support.core.configuration
import java.net.URI
import java.net.URL
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

internal class ProxyAwareResourceRetrieverTest {

    @Test
    fun testNoProxy() {
        var retriever = ProxyAwareResourceRetriever(URL("http://proxy:8080"))
        assertTrue(retriever.shouldProxy(URL("http://www.vg.no")))
        assertFalse(retriever.shouldProxy(URL("http:/www.aetat.no")))
        retriever = ProxyAwareResourceRetriever()
        assertFalse(retriever.shouldProxy(URL("http:/www.aetat.no")))
        assertFalse(retriever.shouldProxy(URL("http://www.vg.no")))
    }

    @Test
    fun testUsePlainTextForHttps() {
        val resourceRetriever = ProxyAwareResourceRetriever(null, true)
        val scheme = "https://"
        val host = "host.domain.no"
        val pathAndQuery = "/somepath?foo=bar&bar=foo"
        val url = URI.create(scheme + host + pathAndQuery).toURL()
        assertEquals("http://$host:443$pathAndQuery",
            resourceRetriever.urlWithPlainTextForHttps(url).toString())
    }
}