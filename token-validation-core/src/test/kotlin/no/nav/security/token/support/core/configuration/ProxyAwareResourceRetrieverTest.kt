package no.nav.security.token.support.core.configuration
import java.net.URI
import java.net.URL
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

internal class ProxyAwareResourceRetrieverTest {

    @Test
    fun testNoProxy() {
        ProxyAwareResourceRetriever(URI.create("http://proxy:8080").toURL()).run {
            assertTrue(shouldProxy(URI.create("http://www.vg.no").toURL()))
            assertFalse(shouldProxy(URI.create("http:/www.aetat.no").toURL()))
        }
         ProxyAwareResourceRetriever().run {
            assertFalse(shouldProxy(URI.create("http:/www.aetat.no").toURL()))
            assertFalse(shouldProxy(URI.create("http://www.vg.no").toURL()))
        }
    }

    @Test
    fun testUsePlainTextForHttps() {
        val resourceRetriever = ProxyAwareResourceRetriever(null, true)
        val url = URI.create("https://host.domain.no/somepath?foo=bar&bar=foo").toURL()
        val plain = resourceRetriever.urlWithPlainTextForHttps(url)
        assertEquals(plain.protocol, "http")
        assertEquals(plain.port, 443)
    }
}