package no.nav.security.token.support.client.spring.oauth2

import com.nimbusds.common.contenttype.ContentType.*
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTClaimNames.JWT_ID
import com.nimbusds.jwt.JWTClaimsSet.Builder
import com.nimbusds.jwt.PlainJWT
import com.nimbusds.oauth2.sdk.GrantType.*
import java.io.IOException
import java.net.URI
import java.net.URLEncoder.*
import java.nio.charset.StandardCharsets.*
import java.time.LocalDateTime.*
import java.time.ZoneId.*
import java.util.*
import java.util.Base64.*
import okhttp3.Headers
import okhttp3.mockwebserver.MockWebServer
import org.assertj.core.api.Assertions.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.Mockito.*
import org.mockito.kotlin.whenever
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.web.client.RestClientAutoConfiguration
import org.springframework.boot.autoconfigure.web.client.RestTemplateAutoConfiguration
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.http.MediaType.*
import org.springframework.test.context.ActiveProfiles
import no.nav.security.token.support.client.core.context.JwtBearerTokenResolver
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenService
import no.nav.security.token.support.client.spring.ClientConfigurationProperties
import no.nav.security.token.support.client.spring.oauth2.TestUtils.jsonResponse
import no.nav.security.token.support.core.JwtTokenConstants.AUTHORIZATION_HEADER
import no.nav.security.token.support.core.context.TokenValidationContext
import no.nav.security.token.support.core.context.TokenValidationContextHolder
import no.nav.security.token.support.core.jwt.JwtToken

@SpringBootTest(classes = [ConfigurationWithCacheEnabledTrue::class, RestClientAutoConfiguration::class])
@ActiveProfiles("test")
internal class OAuth2AccessTokenServiceIntegrationTest {
    @MockBean
    private val tokenValidationContextHolder: TokenValidationContextHolder? = null

    @Autowired
    private lateinit var oAuth2AccessTokenService: OAuth2AccessTokenService

    @Autowired
    private lateinit var  clientConfigurationProperties: ClientConfigurationProperties

    @Autowired
    private lateinit var  assertionResolver: JwtBearerTokenResolver
    private lateinit var server: MockWebServer
    private lateinit var tokenEndpointUrl: URI
    @BeforeEach
    fun setup() {
        server = MockWebServer()
        server.start()
        tokenEndpointUrl = server.url("/oauth2/token").toUri()
    }

    @AfterEach
    @Throws(IOException::class)
    fun teardown() {
        server.shutdown()
    }

    @Test
    fun accessTokenOnBehalfOf() {
         clientConfigurationProperties.registration["example1-onbehalfof"] ?.let { it ->
             with(it.toBuilder().tokenEndpointUrl(tokenEndpointUrl).build()) {
                 server.enqueue(jsonResponse(TOKEN_RESPONSE))
                 whenever(tokenValidationContextHolder!!.getTokenValidationContext()).thenReturn(tokenValidationContext("sub1"))
                 val response = oAuth2AccessTokenService.getAccessToken(this)

                 assertThat(response.accessToken).isNotBlank
                 assertThat(response.expiresAt).isGreaterThan(0)
                 assertThat(response.expiresIn).isGreaterThan(0)

                 val request = server.takeRequest()
                 assertThat(request.headers["Content-Type"]).contains(APPLICATION_FORM_URLENCODED_VALUE)
                 assertThat(decodeCredentials(request.headers)).isEqualTo("${authentication.clientId}:${authentication.clientSecret}")

                 val body = request.body.readUtf8()
                 assertThat(body).contains("grant_type=${encode(JWT_BEARER.value, UTF_8)}")
                 assertThat(body).contains("scope=${encode(scope.joinToString(" "), UTF_8)}")
                 assertThat(body).contains("requested_token_use=on_behalf_of")
                 assertThat(body).contains("assertion=${assertionResolver.token()}")
             }
         }
    }

    @Test
    fun accessTokenUsingTokenExhange() {
        val clientProperties = clientConfigurationProperties.registration["example1-token-exchange1"]?.toBuilder()?.tokenEndpointUrl(tokenEndpointUrl)?.build() ?: fail("clientProperties is null")
        server.enqueue(jsonResponse(TOKEN_RESPONSE))
        whenever(tokenValidationContextHolder!!.getTokenValidationContext()).thenReturn(tokenValidationContext("sub1"))

        val response = oAuth2AccessTokenService.getAccessToken(clientProperties)
        assertThat(response.accessToken).isNotBlank
        assertThat(response.expiresAt).isGreaterThan(0)
        assertThat(response.expiresIn).isGreaterThan(0)

        val request = server.takeRequest()
        val body = request.body.readUtf8()
        assertThat(request.headers["Content-Type"]).contains(APPLICATION_FORM_URLENCODED_VALUE)
        assertThat(body).contains("grant_type=${encode(TOKEN_EXCHANGE.value, UTF_8)}")
        assertThat(body).contains("subject_token=${assertionResolver.token()}")
    }

    @Test
    fun accessTokenClientCredentials() {
        val clientProperties = clientConfigurationProperties.registration["example1-clientcredentials1"]?.toBuilder()?.tokenEndpointUrl(tokenEndpointUrl)?.build() ?: fail("clientProperties is null")
        server.enqueue(jsonResponse(TOKEN_RESPONSE))
        val response = oAuth2AccessTokenService.getAccessToken(clientProperties)
        assertThat(response.accessToken).isNotBlank
        assertThat(response.expiresAt).isGreaterThan(0)
        assertThat(response.expiresIn).isGreaterThan(0)

        val request = server.takeRequest()
        val body = request.body.readUtf8()
        assertThat(request.headers["Content-Type"]).contains(APPLICATION_FORM_URLENCODED_VALUE)
        assertThat(decodeCredentials(request.headers)).isEqualTo("${clientProperties.authentication.clientId}:${clientProperties.authentication.clientSecret}")
        assertThat(body).contains("grant_type=client_credentials")
        assertThat(body).contains("scope=${encode(clientProperties.scope.joinToString(" "), UTF_8)}")
        assertThat(body).doesNotContain("requested_token_use=on_behalf_of")
        assertThat(body).doesNotContain("assertion=")

    }

    companion object {
        private const val TOKEN_RESPONSE = """{
          "token_type": "Bearer",
          "scope": "scope1 scope2",
          "expires_at": 1568141495,
          "ext_expires_in": 3599,
          "expires_in": 3599,
          "access_token": "<base64URL>",
          "refresh_token": "<base64URL>"
       }"""

        private fun decodeCredentials(headers: Headers) = headers[AUTHORIZATION_HEADER]
            ?.takeIf { it.startsWith("Basic ") }
            ?.substring("Basic ".length)
            ?.let { getDecoder().decode(it) }
            ?.let { String(it, UTF_8) }
            ?: fail("Authorization header is not Basic or is null")

        private val log = LoggerFactory.getLogger(OAuth2AccessTokenServiceIntegrationTest::class.java)
        private fun tokenValidationContext(sub: String): TokenValidationContext {
            val expiry = now().atZone(systemDefault()).plusSeconds(60).toInstant()
            val jwt: JWT = PlainJWT(
                Builder()
                    .subject(sub)
                    .audience("thisapi")
                    .issuer("someIssuer")
                    .expirationTime(Date.from(expiry))
                    .claim(JWT_ID, UUID.randomUUID().toString())
                    .build())
            return HashMap<String, JwtToken>().run {
                this["issuer1"] = JwtToken(jwt.serialize())
                TokenValidationContext(this)
            }
        }
    }
}