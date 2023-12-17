package no.nav.security.token.support.core.configuration

import com.nimbusds.jwt.JWTClaimNames.AUDIENCE
import com.nimbusds.jwt.JWTClaimNames.SUBJECT
import java.net.URI
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import no.nav.security.token.support.core.IssuerMockWebServer
import no.nav.security.token.support.core.JwtTokenConstants.AUTHORIZATION_HEADER
import no.nav.security.token.support.core.configuration.IssuerProperties.JwksCache
import no.nav.security.token.support.core.configuration.IssuerProperties.Validation
import no.nav.security.token.support.core.exceptions.MetaDataNotAvailableException

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
        assertThat(IssuerConfiguration("issuer1", IssuerProperties(issuerMockWebServer.discoveryUrl, listOf("audience1")),
            ProxyAwareResourceRetriever()).metadata)
            .extracting(
                { it.issuer != null },
                { it.jwkSetURI != null })
            .containsExactly(true, true)
    }

    @Test
    fun issuerConfigurationDiscoveryUrlNotValid() {
        assertThrows<MetaDataNotAvailableException> {
            IssuerConfiguration("issuer1", IssuerProperties(URI("http://notvalid").toURL(), listOf("audience1")))
        }
        assertThrows<MetaDataNotAvailableException> {
            IssuerConfiguration("issuer1", IssuerProperties(URI("http://localhost").toURL(), listOf("audience1")))
        }
        assertThrows<MetaDataNotAvailableException> {
            IssuerConfiguration("issuer1", IssuerProperties(URI.create(issuerMockWebServer.discoveryUrl.toString() + "/pathincorrect").toURL(), listOf("audience1")), ProxyAwareResourceRetriever())
        }
    }

    @Test
    fun issuerConfigurationWithConfigurableJwtTokenValidator() {
        val p = IssuerProperties(issuerMockWebServer.discoveryUrl, emptyList(), null, AUTHORIZATION_HEADER, Validation(listOf(SUBJECT, AUDIENCE)))
        assertThat(IssuerConfiguration("issuer1", p).metadata)
            .extracting(
                { it.issuer != null },
                { it.jwkSetURI != null })
            .containsExactly(true, true)
        assertTrue(p.validation.isConfigured)
    }

    @Test
    fun issuerConfigurationWithConfigurableJWKSCacheAndConfigurableJwtTokenValidator() {
        val p = IssuerProperties(issuerMockWebServer.discoveryUrl, emptyList(), null, AUTHORIZATION_HEADER, Validation(listOf(SUBJECT, AUDIENCE)), JwksCache(15L, 5L))
        assertThat(IssuerConfiguration("issuer1", p).metadata)
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