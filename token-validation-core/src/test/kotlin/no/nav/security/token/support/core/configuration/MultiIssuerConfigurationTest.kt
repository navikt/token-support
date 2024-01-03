package no.nav.security.token.support.core.configuration

import com.nimbusds.jose.util.DefaultResourceRetriever
import java.net.Proxy.Type.HTTP
import java.net.URL
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import no.nav.security.token.support.core.IssuerMockWebServer
import no.nav.security.token.support.core.JwtTokenConstants.AUTHORIZATION_HEADER
import no.nav.security.token.support.core.configuration.IssuerProperties.JwksCache.Companion.EMPTY_CACHE
import no.nav.security.token.support.core.configuration.IssuerProperties.Validation.Companion.EMPTY

internal class MultiIssuerConfigurationTest {

    private lateinit var issuerMockWebServer : IssuerMockWebServer
    private lateinit var discoveryUrl : URL
    private  var proxyUrl : URL? = null
    @BeforeEach
    fun setup() {
        issuerMockWebServer = IssuerMockWebServer()
        issuerMockWebServer.start()
        discoveryUrl = issuerMockWebServer.discoveryUrl
        proxyUrl = issuerMockWebServer.proxyUrl
    }

    @AfterEach
    fun teardown() {
        issuerMockWebServer.shutdown()
    }

    @Test
    fun issuerConfiguration() {
        "issuer1".run {
            assertPopulated(this, MultiIssuerConfiguration(mapOf(this to IssuerProperties(discoveryUrl, listOf("audience1")))))
        }
    }

    @Test
    fun issuerConfigurationWithProxy () {
            val issuerProperties = IssuerProperties(discoveryUrl, listOf("audience1"), null, AUTHORIZATION_HEADER, EMPTY, EMPTY_CACHE, proxyUrl)
            val issuerName = "issuer1"
            val cfg = MultiIssuerConfiguration(mapOf(issuerName to issuerProperties))
            assertPopulated(issuerName, cfg)
            val config = cfg.issuers[issuerName]
            assertThat(config).isNotNull()
            assertThat(config?.resourceRetriever).isInstanceOf(ProxyAwareResourceRetriever::class.java)
            assertThat((config?.resourceRetriever as DefaultResourceRetriever).proxy.type()).isEqualTo(HTTP)
        }

    private fun assertPopulated(issuerName : String, cfg : MultiIssuerConfiguration) {
        assertThat(cfg.issuerShortNames).containsExactly(issuerName)
        assertThat(cfg.issuers[issuerName]?.metadata)
            .isNotNull()
            .extracting(
                { it?.issuer != null },
                { it?.issuer?.value != null },
                { it?.issuer?.value == "\$ISSUER" })
            .containsExactly(true, true,true)
    }
}