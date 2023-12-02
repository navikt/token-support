package no.nav.security.token.support.client.core.oauth2

import com.nimbusds.jwt.JWTClaimsSet.Builder
import com.nimbusds.jwt.PlainJWT
import com.nimbusds.oauth2.sdk.GrantType
import java.time.Instant
import java.time.LocalDateTime.*
import java.time.ZoneId.*
import java.util.Arrays
import java.util.Date
import java.util.Optional
import java.util.UUID
import org.assertj.core.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.Mock
import org.mockito.Mockito
import org.mockito.Mockito.never
import org.mockito.Mockito.reset
import org.mockito.Mockito.times
import org.mockito.Mockito.verify
import org.mockito.Mockito.`when`
import org.mockito.MockitoAnnotations
import no.nav.security.token.support.client.core.ClientProperties.TokenExchangeProperties
import no.nav.security.token.support.client.core.OAuth2CacheFactory.accessTokenResponseCache
import no.nav.security.token.support.client.core.OAuth2ClientException
import no.nav.security.token.support.client.core.TestUtils.clientProperties
import no.nav.security.token.support.client.core.context.JwtBearerTokenResolver

internal class OAuth2AccessTokenServiceTest {

    private inline fun <reified T> reifiedAny(type: Class<T>): T = Mockito.any(type)


    @Mock
    private lateinit var onBehalfOfTokenResponseClient : OnBehalfOfTokenClient

    @Mock
    private lateinit var clientCredentialsTokenResponseClient : ClientCredentialsTokenClient

    @Mock
    private lateinit var exchangeTokeResponseClient : TokenExchangeClient

    @Mock
    private lateinit var assertionResolver : JwtBearerTokenResolver
    private lateinit var oAuth2AccessTokenService : OAuth2AccessTokenService

    @BeforeEach
    fun setup() {
       MockitoAnnotations.openMocks(this)
        val oboCache = accessTokenResponseCache<OnBehalfOfGrantRequest>(10, 1)
        val clientCredentialsCache = accessTokenResponseCache<ClientCredentialsGrantRequest>(10, 1)
        val exchangeTokenCache = accessTokenResponseCache<TokenExchangeGrantRequest>(10, 1)
        oAuth2AccessTokenService = OAuth2AccessTokenService(assertionResolver, onBehalfOfTokenResponseClient, clientCredentialsTokenResponseClient, exchangeTokeResponseClient)
        oAuth2AccessTokenService.onBehalfOfGrantCache = oboCache
        oAuth2AccessTokenService.clientCredentialsGrantCache = clientCredentialsCache
        oAuth2AccessTokenService.exchangeGrantCache = exchangeTokenCache
    }


    @Test
    fun accessTokenOnBehalfOf() {
            `when`(assertionResolver.token()).thenReturn(Optional.of(jwt("sub1").serialize()))
            val firstAccessToken = "first_access_token"
            `when`(onBehalfOfTokenResponseClient.getTokenResponse(reifiedAny(OnBehalfOfGrantRequest::class.java)))
                .thenReturn(accessTokenResponse(firstAccessToken, 60))
            val res = oAuth2AccessTokenService.getAccessToken(onBehalfOfProperties())
            verify(onBehalfOfTokenResponseClient).getTokenResponse(reifiedAny( OnBehalfOfGrantRequest::class.java))
            assertThat(res).hasNoNullFieldsOrProperties()
            assertThat(res!!.accessToken).isEqualTo("first_access_token")
        }

    @Test
    fun accessTokenClientCredentials()  {
        val firstAccessToken = "first_access_token"
            `when`(clientCredentialsTokenResponseClient.getTokenResponse(reifiedAny(ClientCredentialsGrantRequest::class.java)))
                .thenReturn(accessTokenResponse(firstAccessToken, 60))
            val res = oAuth2AccessTokenService.getAccessToken(clientCredentialsProperties())
            verify(clientCredentialsTokenResponseClient).getTokenResponse(reifiedAny(ClientCredentialsGrantRequest::class.java))
            assertThat(res).hasNoNullFieldsOrProperties()
            assertThat(res!!.accessToken).isEqualTo("first_access_token")
        }

    @Test
    fun accessTokenOnBehalfOfNoAuthenticatedTokenFound()  {
            assertThatExceptionOfType(OAuth2ClientException::class.java)
                .isThrownBy { oAuth2AccessTokenService.getAccessToken(onBehalfOfProperties()) }
                .withMessageContaining("no authenticated jwt token found in validation context, cannot do on-behalf-of")
        }

    @Test
    fun accessTokenOnBehalfOf_WithCache_MultipleTimes_SameClientConfig() {
            val clientProperties = onBehalfOfProperties()
            `when`(assertionResolver.token()).thenReturn(Optional.of(jwt("sub1").serialize()))

            //should invoke client and populate cache
            val firstAccessToken = "first_access_token"
            `when`(onBehalfOfTokenResponseClient.getTokenResponse(reifiedAny(OnBehalfOfGrantRequest::class.java)))
                .thenReturn(accessTokenResponse(firstAccessToken, 60))
            val res = oAuth2AccessTokenService.getAccessToken(clientProperties)
            verify(onBehalfOfTokenResponseClient).getTokenResponse(reifiedAny(OnBehalfOfGrantRequest::class.java))
            assertThat(res).hasNoNullFieldsOrProperties()
            assertThat(res!!.accessToken).isEqualTo("first_access_token")

            //should get response from cache and NOT invoke client
            reset(onBehalfOfTokenResponseClient)
            val res2 = oAuth2AccessTokenService.getAccessToken(clientProperties)
            verify(onBehalfOfTokenResponseClient, never()).getTokenResponse(reifiedAny(OnBehalfOfGrantRequest::class.java))
            assertThat(res2!!.accessToken).isEqualTo("first_access_token")

            //another user/token but same clientconfig, should invoke client and populate cache
            reset(assertionResolver)
            `when`(assertionResolver.token()).thenReturn(Optional.of(jwt("sub2").serialize()))
            reset(onBehalfOfTokenResponseClient)
            val secondAccessToken = "second_access_token"
            `when`(onBehalfOfTokenResponseClient.getTokenResponse(reifiedAny(OnBehalfOfGrantRequest::class.java)))
                .thenReturn(accessTokenResponse(secondAccessToken, 60))
            val res3 = oAuth2AccessTokenService.getAccessToken(clientProperties)
            verify(onBehalfOfTokenResponseClient).getTokenResponse(reifiedAny(OnBehalfOfGrantRequest::class.java))
            assertThat(res3!!.accessToken).isEqualTo(secondAccessToken)
        }

    @Test
    fun accessTokenClientCredentials_WithCache_MultipleTimes()  {
            var clientProperties = clientCredentialsProperties()

            //should invoke client and populate cache
            val firstAccessToken = "first_access_token"
            `when`(clientCredentialsTokenResponseClient.getTokenResponse(reifiedAny(
                ClientCredentialsGrantRequest::class.java)))
                .thenReturn(accessTokenResponse(firstAccessToken, 60))
            val res1 = oAuth2AccessTokenService.getAccessToken(clientProperties)
            verify(clientCredentialsTokenResponseClient).getTokenResponse(reifiedAny(ClientCredentialsGrantRequest::class.java))
            assertThat(res1).hasNoNullFieldsOrProperties()
            assertThat(res1!!.accessToken).isEqualTo("first_access_token")

            //should get response from cache and NOT invoke client
            reset(clientCredentialsTokenResponseClient)
            val res2 = oAuth2AccessTokenService.getAccessToken(clientProperties)
            verify(clientCredentialsTokenResponseClient, never()).getTokenResponse(reifiedAny(
                ClientCredentialsGrantRequest::class.java))
            assertThat(res2!!.accessToken).isEqualTo("first_access_token")

            //another clientconfig, should invoke client and populate cache
            clientProperties = clientCredentialsProperties("scope3")
            reset(clientCredentialsTokenResponseClient)
            val secondAccessToken = "second_access_token"
            `when`(clientCredentialsTokenResponseClient.getTokenResponse(reifiedAny(ClientCredentialsGrantRequest::class.java)))
                .thenReturn(accessTokenResponse(secondAccessToken, 60))
            val res3 = oAuth2AccessTokenService.getAccessToken(clientProperties)
            verify(clientCredentialsTokenResponseClient).getTokenResponse(reifiedAny(ClientCredentialsGrantRequest::class.java))
            assertThat(res3!!.accessToken).isEqualTo(secondAccessToken)
        }

    @Test
    @Throws(InterruptedException::class)
    fun testCacheEntryIsEvictedOnExpiry() {
        val clientProperties = onBehalfOfProperties()
        `when`(assertionResolver.token()).thenReturn(Optional.of(jwt("sub1").serialize()))

        //should invoke client and populate cache
        val firstAccessToken = "first_access_token"
        `when`(onBehalfOfTokenResponseClient.getTokenResponse(reifiedAny(OnBehalfOfGrantRequest::class.java)))
            .thenReturn(accessTokenResponse(firstAccessToken, 1))
        val res1 = oAuth2AccessTokenService.getAccessToken(clientProperties)
        verify(onBehalfOfTokenResponseClient).getTokenResponse(reifiedAny(OnBehalfOfGrantRequest::class.java))
        assertThat(res1).hasNoNullFieldsOrProperties()
        assertThat(res1!!.accessToken).isEqualTo("first_access_token")
        Thread.sleep(1000)

        //entry should be missing from cache due to expiry
        reset(onBehalfOfTokenResponseClient)
        val secondAccessToken = "second_access_token"
        `when`(onBehalfOfTokenResponseClient.getTokenResponse(reifiedAny(OnBehalfOfGrantRequest::class.java)))
            .thenReturn(accessTokenResponse(secondAccessToken, 1))
        val res2 = oAuth2AccessTokenService.getAccessToken(clientProperties)
        verify(onBehalfOfTokenResponseClient).getTokenResponse(reifiedAny(OnBehalfOfGrantRequest::class.java))
        assertThat(res2!!.accessToken).isEqualTo(secondAccessToken)
    }

    @Test
    fun accessTokenExchange() {
            val clientProperties = exchangeProperties()
            `when`(assertionResolver.token()).thenReturn(Optional.of(jwt("sub1").serialize()))
            val firstAccessToken = "first_access_token"
            `when`(exchangeTokeResponseClient.getTokenResponse(reifiedAny(
                TokenExchangeGrantRequest::class.java)))
                .thenReturn(accessTokenResponse(firstAccessToken, 60))
            val res1 = oAuth2AccessTokenService.getAccessToken(clientProperties)
            verify(exchangeTokeResponseClient, times(1)).getTokenResponse(reifiedAny(
                TokenExchangeGrantRequest::class.java))
            assertThat(res1).hasNoNullFieldsOrProperties()
            assertThat(res1!!.accessToken).isEqualTo("first_access_token")
        }

    companion object {

        private fun jwt(sub : String) = PlainJWT(Builder()
            .subject(sub)
            .audience("thisapi")
            .issuer("someIssuer")
            .expirationTime(Date.from(now().atZone(systemDefault()).plusSeconds(60).toInstant()))
            .claim("jti", UUID.randomUUID().toString())
            .build())

        private fun clientCredentialsProperties() = clientCredentialsProperties("scope1", "scope2")

        private fun clientCredentialsProperties(vararg scope : String) =
            clientProperties("http://token", GrantType.CLIENT_CREDENTIALS)
                .toBuilder()
                .scope(Arrays.asList(*scope))
                .build()

        private fun exchangeProperties(audience : String = "audience") =
            clientProperties("http://token", GrantType.TOKEN_EXCHANGE)
                .toBuilder()
                .tokenExchange(TokenExchangeProperties(audience))
                .build()

        private fun onBehalfOfProperties() = clientProperties("http://token", GrantType.JWT_BEARER)

        private fun accessTokenResponse(assertion : String, expiresIn : Int) =
            OAuth2AccessTokenResponse(assertion, Math.toIntExact(Instant.now().plusSeconds(expiresIn.toLong()).epochSecond), expiresIn)
    }
}