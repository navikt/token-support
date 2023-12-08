package no.nav.security.token.support.core.configuration
import java.net.URI
import java.net.URL
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

internal class ProxyAwareResourceRetrieverTest {

    @Test
    fun testNoProxy() {
        ProxyAwareResourceRetriever(URL("http://proxy:8080")).run {
            assertTrue(shouldProxy(URL("http://www.vg.no")))
            assertFalse(shouldProxy(URL("http:/www.aetat.no")))
        }
         ProxyAwareResourceRetriever().run {
            assertFalse(shouldProxy(URL("http:/www.aetat.no")))
            assertFalse(shouldProxy(URL("http://www.vg.no")))
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