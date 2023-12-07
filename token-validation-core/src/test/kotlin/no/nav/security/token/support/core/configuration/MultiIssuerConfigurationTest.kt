package no.nav.security.token.support.core.configuration

import com.nimbusds.jose.util.DefaultResourceRetriever
import java.io.IOException
import java.net.URL
import java.util.Map
import org.assertj.core.api.Assertions
import org.assertj.core.api.Assertions.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.slf4j.LoggerFactory
import no.nav.security.token.support.core.IssuerMockWebServer
import no.nav.security.token.support.core.JwtTokenConstants.AUTHORIZATION_HEADER
import no.nav.security.token.support.core.configuration.IssuerProperties.JwksCache
import no.nav.security.token.support.core.configuration.IssuerProperties.Validation

internal class MultiIssuerConfigurationTest {

    private var issuerMockWebServer : IssuerMockWebServer? = null
    private var discoveryUrl : URL? = null
    private var proxyUrl : URL? = null
    @BeforeEach
    @Throws(IOException::class)
    fun setup() {
        issuerMockWebServer = IssuerMockWebServer()
        issuerMockWebServer!!.start()
        discoveryUrl = issuerMockWebServer!!.discoveryUrl
        proxyUrl = issuerMockWebServer!!.proxyUrl
    }

    @AfterEach
    @Throws(IOException::class)
    fun teardown() {
        issuerMockWebServer!!.shutdown()
    }

    @Test
    fun issuerConfiguration()  {
            val issuerProperties = IssuerProperties(discoveryUrl!!, listOf("audience1"))
            val issuerName = "issuer1"
            val multiIssuerConfiguration = MultiIssuerConfiguration(Map.of(issuerName, issuerProperties))
            assertThatMultiIssuerConfigurationIsPopulatedFromMetadata(issuerName, multiIssuerConfiguration)
        }

    @Test
    fun issuerConfigurationWithProxy () {
            val issuerProperties =
                IssuerProperties(discoveryUrl!!, listOf<String>("audience1"), null, AUTHORIZATION_HEADER, Validation.EMPTY, JwksCache.EMPTY_CACHE, proxyUrl)
            val issuerName = "issuer1"
            val multiIssuerConfiguration = MultiIssuerConfiguration(Map.of(issuerName, issuerProperties))
            assertThatMultiIssuerConfigurationIsPopulatedFromMetadata(issuerName, multiIssuerConfiguration)
            val config = multiIssuerConfiguration.getIssuer(issuerName).orElse(null)
            assertThat(config).isNotNull()
            assertThat(config.resourceRetriever).isInstanceOf(DefaultResourceRetriever::class.java)
            assertThat((config.resourceRetriever as DefaultResourceRetriever).proxy).isNotNull()
        }

    private fun assertThatMultiIssuerConfigurationIsPopulatedFromMetadata(issuerName : String,
                                                                          multiIssuerConfiguration : MultiIssuerConfiguration) {
        assertThat(multiIssuerConfiguration.getIssuerShortNames()).containsExactly(issuerName)
        val config = multiIssuerConfiguration.getIssuer(issuerName).orElse(null)
        assertThat(config).isNotNull()
        assertThat(config.name).isEqualTo(issuerName)
        assertThat(config.tokenValidator).isNotNull()
        assertThat(config.metadata).isNotNull()
        assertThat(config.metadata.issuer).isNotNull()
        assertThat(config.metadata.issuer.value).isEqualTo("\$ISSUER")
        assertThat(config.resourceRetriever).isNotNull()
    }
}