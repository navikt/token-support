package no.nav.security.token.support.core.configuration

import java.io.IOException
import java.net.URI
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import no.nav.security.token.support.core.IssuerMockWebServer
import no.nav.security.token.support.core.JwtTokenConstants.AUTHORIZATION_HEADER
import no.nav.security.token.support.core.configuration.IssuerProperties.JwksCache
import no.nav.security.token.support.core.configuration.IssuerProperties.Validation
import no.nav.security.token.support.core.exceptions.MetaDataNotAvailableException
import no.nav.security.token.support.core.validation.DefaultConfigurableJwtValidator

internal class IssuerConfigurationTest {

    private var issuerMockWebServer : IssuerMockWebServer? = null
    @BeforeEach
    @Throws(IOException::class)
    fun setup() {
        issuerMockWebServer = IssuerMockWebServer(false)
        issuerMockWebServer!!.start()
    }

    @AfterEach
    @Throws(IOException::class)
    fun after() {
        issuerMockWebServer!!.shutdown()
    }

    @Test
    fun issuerConfigurationWithMetadataFromDiscoveryUrl() {
        val config = IssuerConfiguration(
            "issuer1", IssuerProperties(issuerMockWebServer!!.discoveryUrl, listOf("audience1")), ProxyAwareResourceRetriever())
        Assertions.assertThat(config.metadata).isNotNull()
        Assertions.assertThat(config.tokenValidator).isNotNull()
        Assertions.assertThat(config.tokenValidator).isInstanceOf(DefaultConfigurableJwtValidator::class.java)
        val metadata = config.metadata
        Assertions.assertThat(metadata.issuer).isNotNull()
        Assertions.assertThat(metadata.jwkSetURI.toString()).isNotNull()
    }

    @Test
    fun issuerConfigurationDiscoveryUrlNotValid() {
        Assertions.assertThatExceptionOfType(MetaDataNotAvailableException::class.java).isThrownBy {
            IssuerConfiguration(
                "issuer1",
                IssuerProperties(URI.create("http://notvalid").toURL(), listOf("audience1")),
                ProxyAwareResourceRetriever())
        }
        Assertions.assertThatExceptionOfType(MetaDataNotAvailableException::class.java).isThrownBy {
            IssuerConfiguration(
                "issuer1",
                IssuerProperties(URI.create("http://localhost").toURL(), listOf("audience1")),
                ProxyAwareResourceRetriever())
        }
        Assertions.assertThatExceptionOfType(MetaDataNotAvailableException::class.java).isThrownBy {
            IssuerConfiguration(
                "issuer1",
                IssuerProperties(URI.create(issuerMockWebServer!!.discoveryUrl.toString() + "/pathincorrect").toURL(), listOf("audience1")),
                ProxyAwareResourceRetriever())
        }
    }

    @Test
    fun issuerConfigurationWithConfigurableJwtTokenValidator() {
        val issuerProperties = IssuerProperties(
            issuerMockWebServer!!.discoveryUrl, emptyList<String>(), null, AUTHORIZATION_HEADER, Validation(listOf<String>("sub", "aud"))
                                               )
        val config = IssuerConfiguration(
            "issuer1",
            issuerProperties,
            ProxyAwareResourceRetriever()
                                        )
        Assertions.assertThat(config.metadata).isNotNull()
        Assertions.assertThat(config.tokenValidator).isNotNull()
        Assertions.assertThat(config.tokenValidator).isInstanceOf(DefaultConfigurableJwtValidator::class.java)
        val metadata = config.metadata
        Assertions.assertThat(metadata.issuer).isNotNull()
        Assertions.assertThat(metadata.jwkSetURI.toString()).isNotNull()
        org.junit.jupiter.api.Assertions.assertTrue(issuerProperties.validation.isConfigured)
    }

    @Test
    fun issuerConfigurationWithConfigurableJWKSCacheAndConfigurableJwtTokenValidator() {
        val issuerProperties = IssuerProperties(
            issuerMockWebServer!!.discoveryUrl, emptyList<String>(), null, AUTHORIZATION_HEADER,
            Validation(listOf<String>("sub", "aud")),
            JwksCache(15L, 5L)
                                               )
        val config = IssuerConfiguration(
            "issuer1",
            issuerProperties,
            ProxyAwareResourceRetriever()
                                        )
        Assertions.assertThat(config.metadata).isNotNull()
        Assertions.assertThat(config.tokenValidator).isNotNull()
        Assertions.assertThat(config.tokenValidator).isInstanceOf(DefaultConfigurableJwtValidator::class.java)
        val metadata = config.metadata
        Assertions.assertThat(metadata.issuer).isNotNull()
        Assertions.assertThat(metadata.jwkSetURI.toString()).isNotNull()
        org.junit.jupiter.api.Assertions.assertTrue(issuerProperties.jwksCache.isConfigured)
        org.junit.jupiter.api.Assertions.assertTrue(issuerProperties.validation.isConfigured)
    }
}