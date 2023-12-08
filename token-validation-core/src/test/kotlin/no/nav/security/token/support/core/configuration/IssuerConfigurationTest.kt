package no.nav.security.token.support.core.configuration

import java.net.URI
import java.net.URL
import org.assertj.core.api.Assertions.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import no.nav.security.token.support.core.IssuerMockWebServer
import no.nav.security.token.support.core.JwtTokenConstants.AUTHORIZATION_HEADER
import no.nav.security.token.support.core.configuration.IssuerProperties.JwksCache
import no.nav.security.token.support.core.configuration.IssuerProperties.Validation
import no.nav.security.token.support.core.exceptions.MetaDataNotAvailableException
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.assertThrows

internal class IssuerConfigurationTest {

    private lateinit var issuerMockWebServer : IssuerMockWebServer
    @BeforeEach
    fun setup() {
        issuerMockWebServer = IssuerMockWebServer(false).apply {
            start()
        }
    }

    @AfterEach
    fun after() {
        issuerMockWebServer.shutdown()
    }

    @Test
    fun issuerConfigurationWithMetadataFromDiscoveryUrl() {
        val config = IssuerConfiguration("issuer1", IssuerProperties(issuerMockWebServer.discoveryUrl, listOf("audience1")), ProxyAwareResourceRetriever())
        assertThat(config.metadata)
            .extracting(
                { it.issuer != null },
                { it.jwkSetURI != null })
            .containsExactly(true, true)
    }

    @Test
    fun issuerConfigurationDiscoveryUrlNotValid() {
        assertThrows<MetaDataNotAvailableException> {
            IssuerConfiguration("issuer1", IssuerProperties(URL("http://notvalid"), listOf("audience1")))
        }
        assertThrows<MetaDataNotAvailableException> {
            IssuerConfiguration("issuer1", IssuerProperties(URL("http://localhost"), listOf("audience1")))
        }
        assertThrows<MetaDataNotAvailableException> {
            IssuerConfiguration("issuer1", IssuerProperties(URI.create(issuerMockWebServer.discoveryUrl.toString() + "/pathincorrect").toURL(), listOf("audience1")), ProxyAwareResourceRetriever())
        }
    }

    @Test
    fun issuerConfigurationWithConfigurableJwtTokenValidator() {
        val p = IssuerProperties(issuerMockWebServer.discoveryUrl, emptyList(), null, AUTHORIZATION_HEADER, Validation(listOf("sub", "aud")))
        val config = IssuerConfiguration("issuer1", p)
        assertThat(config.metadata)
            .extracting(
                { it.issuer != null },
                { it.jwkSetURI != null })
            .containsExactly(true, true)
        assertTrue(p.validation.isConfigured)
    }

    @Test
    fun issuerConfigurationWithConfigurableJWKSCacheAndConfigurableJwtTokenValidator() {
        val p = IssuerProperties(issuerMockWebServer.discoveryUrl, emptyList(), null, AUTHORIZATION_HEADER, Validation(listOf("sub", "aud")), JwksCache(15L, 5L))
        val config = IssuerConfiguration("issuer1", p)
        assertThat(config.metadata)
            .extracting(
                { it.issuer != null },
                { it.jwkSetURI != null })
            .containsExactly(true, true)
        assertThat(p)
            .extracting(
                { it.jwksCache.isConfigured},
                { it.validation.isConfigured })
            .containsExactly(true, true)
    }
}