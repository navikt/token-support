package validation

import com.nimbusds.jose.jwk.source.JWKSetBasedJWKSource
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.jwk.source.JWKSourceBuilder
import com.nimbusds.jose.jwk.source.RefreshAheadCachingJWKSetSource
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.util.ResourceRetriever
import com.nimbusds.oauth2.sdk.`as`.AuthorizationServerMetadata
import com.nimbusds.oauth2.sdk.id.Issuer
import java.net.URI
import java.net.URL
import java.util.concurrent.TimeUnit.MINUTES
import org.assertj.core.api.Assertions
import org.assertj.core.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.Mock
import org.mockito.Mockito
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.junit.jupiter.MockitoSettings
import org.mockito.quality.Strictness.LENIENT
import no.nav.security.token.support.core.JwtTokenConstants.AUTHORIZATION_HEADER
import no.nav.security.token.support.core.configuration.IssuerProperties
import no.nav.security.token.support.core.configuration.IssuerProperties.JwksCache
import no.nav.security.token.support.core.configuration.IssuerProperties.Validation
import no.nav.security.token.support.core.validation.DefaultConfigurableJwtValidator
import no.nav.security.token.support.core.validation.JwtTokenValidator
import no.nav.security.token.support.core.validation.JwtTokenValidatorFactory.tokenValidator

@ExtendWith(MockitoExtension::class)
@MockitoSettings(strictness = LENIENT)
internal class JwtTokenValidatorFactoryTest {

    @Mock
    private lateinit var metadata : AuthorizationServerMetadata

    @Mock
    private lateinit var resourceRetriever : ResourceRetriever
    private val url = URL("http://url")
    private var issuerProperties = IssuerProperties(url, listOf("aud1"))

    @BeforeEach
    fun setup() {
        Mockito.`when`(metadata.getJWKSetURI()).thenReturn(URI.create("http://someurl"))
        Mockito.`when`(metadata.getIssuer()).thenReturn(Issuer("myissuer"))
    }

    @Test
    fun createDefaultTokenValidator() {
        val defaultValidator = tokenValidator(issuerProperties, metadata, resourceRetriever)
        assertThat(defaultValidator).isInstanceOf(DefaultConfigurableJwtValidator::class.java)

        val source : JWKSource<SecurityContext> = getJwkSource(defaultValidator)
        assertThat(source).isInstanceOf(JWKSetBasedJWKSource::class.java)

        val basedSource = (source as JWKSetBasedJWKSource<*>)
        assertThat(basedSource.jwkSetSource).isInstanceOf(RefreshAheadCachingJWKSetSource::class.java)

        val cache : RefreshAheadCachingJWKSetSource<*> = (basedSource.jwkSetSource as RefreshAheadCachingJWKSetSource<*>)
        assertThat(cache.timeToLive).isEqualTo(MINUTES.toMillis(15))
        assertThat(cache.cacheRefreshTimeout).isEqualTo(MINUTES.toMillis(5))
    }

    @Test
    fun createTokenValidatorWithOptionalClaim() {
        issuerProperties = IssuerProperties(url, emptyList(), null, AUTHORIZATION_HEADER, Validation(listOf("optionalclaim")), JwksCache.EMPTY_CACHE)
        val validatorWithDefaultCache = tokenValidator(issuerProperties, metadata, resourceRetriever)
        assertThat(validatorWithDefaultCache).isInstanceOf(DefaultConfigurableJwtValidator::class.java)
    }

    @Test
    fun createTokenValidatorWithCustomJwksCache() {
        val jwksCacheProperties = JwksCache(5L, 1L)
        issuerProperties = IssuerProperties(url, emptyList(), null, AUTHORIZATION_HEADER, Validation(listOf("optionalclaim")), jwksCacheProperties)

        val validatorWithCustomCache = tokenValidator(issuerProperties, metadata, resourceRetriever)
        assertThat(validatorWithCustomCache).isInstanceOf(DefaultConfigurableJwtValidator::class.java)

        val source  = getJwkSource(validatorWithCustomCache)
        assertThat(source).isInstanceOf(JWKSetBasedJWKSource::class.java)

        val basedSource = (source as JWKSetBasedJWKSource<*>)
        assertThat(basedSource.jwkSetSource).isInstanceOf(RefreshAheadCachingJWKSetSource::class.java)

        val cache = (basedSource.jwkSetSource as RefreshAheadCachingJWKSetSource<*>)
        assertThat(cache.timeToLive).isEqualTo(jwksCacheProperties.lifespanMillis)
        assertThat(cache.cacheRefreshTimeout).isEqualTo(jwksCacheProperties.refreshTimeMillis)
    }

    @Test
    fun createTokenValidatorWithProvidedJwkSource() {
        val jwkSource  = JWKSourceBuilder.create<SecurityContext>(url)
            .cache(MINUTES.toMillis(5), MINUTES.toMillis(1))
            .build()
        val jwtTokenValidator = tokenValidator(issuerProperties, metadata, jwkSource)
        assertThat(getJwkSource(jwtTokenValidator)).isEqualTo(jwkSource)
    }

    companion object {

        private fun getJwkSource(jwtTokenValidator : JwtTokenValidator) = (jwtTokenValidator as DefaultConfigurableJwtValidator).jwkSource
    }
}