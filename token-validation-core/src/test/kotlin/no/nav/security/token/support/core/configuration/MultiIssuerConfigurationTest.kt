package no.nav.security.token.support.core.configuration

import com.nimbusds.jose.util.DefaultResourceRetriever
import java.net.Proxy.Type.*
import java.net.URL
import org.assertj.core.api.Assertions.*
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
    fun issuerConfiguration()  {
            val issuerProperties = IssuerProperties(discoveryUrl, listOf("audience1"))
            val issuerName = "issuer1"
            val multiIssuerConfiguration = MultiIssuerConfiguration(mapOf(issuerName to issuerProperties))
            assertThatMultiIssuerConfigurationIsPopulatedFromMetadata(issuerName, multiIssuerConfiguration)
        }

    @Test
    fun issuerConfigurationWithProxy () {
            val issuerProperties = IssuerProperties(discoveryUrl, listOf("audience1"), null, AUTHORIZATION_HEADER, EMPTY, EMPTY_CACHE, proxyUrl)
            val issuerName = "issuer1"
            val multiIssuerConfiguration = MultiIssuerConfiguration(mapOf(issuerName to issuerProperties))
            assertThatMultiIssuerConfigurationIsPopulatedFromMetadata(issuerName, multiIssuerConfiguration)
            val config = multiIssuerConfiguration.issuers[issuerName]
            assertThat(config).isNotNull()
            assertThat(config?.resourceRetriever).isInstanceOf(ProxyAwareResourceRetriever::class.java)
            assertThat((config?.resourceRetriever as DefaultResourceRetriever).proxy.type()).isEqualTo(HTTP)
        }

    private fun assertThatMultiIssuerConfigurationIsPopulatedFromMetadata(issuerName : String, multiIssuerConfiguration : MultiIssuerConfiguration) {
        assertThat(multiIssuerConfiguration.getIssuerShortNames()).containsExactly(issuerName)
        val config = multiIssuerConfiguration.issuers[issuerName]
        assertThat(config).isNotNull()
        assertThat(config?.name).isEqualTo(issuerName)
        assertThat(config?.tokenValidator).isNotNull()
        assertThat(config?.metadata).isNotNull()
        assertThat(config?.metadata?.issuer).isNotNull()
        assertThat(config?.metadata?.issuer?.value).isEqualTo("\$ISSUER")
        assertThat(config?.resourceRetriever).isNotNull()
    }
}