package no.nav.security.token.support.client.spring.oauth2

import com.nimbusds.jwt.JWTClaimsSet.Builder
import com.nimbusds.oauth2.sdk.GrantType.*
import java.net.URLEncoder.*
import java.nio.charset.StandardCharsets.*
import java.time.LocalDateTime.*
import java.time.ZoneId.*
import java.util.*
import org.assertj.core.api.Assertions.*
import org.mockito.Mockito.*
import org.springframework.http.MediaType.*
import no.nav.security.token.support.core.JwtTokenConstants.AUTHORIZATION_HEADER
import no.nav.security.token.support.core.context.TokenValidationContextHolder
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.PlainJWT
import com.nimbusds.oauth2.sdk.GrantType
import no.nav.security.token.support.client.core.context.JwtBearerTokenResolver
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenService
import no.nav.security.token.support.client.spring.ClientConfigurationProperties
import no.nav.security.token.support.core.context.TokenValidationContext
import no.nav.security.token.support.core.jwt.JwtToken
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.Mockito
import org.mockito.MockitoAnnotations
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.test.context.ActiveProfiles
import java.io.IOException
import java.net.URI
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.time.LocalDateTime
import java.time.ZoneId
@SpringBootTest(classes = [ConfigurationWithCacheEnabledTrue::class])
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
    @Throws(IOException::class)
    fun setup() {
        MockitoAnnotations.openMocks(this)
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
        var clientProperties = clientConfigurationProperties.registration["example1-onbehalfof"]
        assertThat(clientProperties).isNotNull
        clientProperties = clientProperties!!.toBuilder()
            .tokenEndpointUrl(tokenEndpointUrl)
            .build()
        server.enqueue(TestUtils.jsonResponse(TOKEN_RESPONSE))
        Mockito.`when`(tokenValidationContextHolder!!.getTokenValidationContext())
            .thenReturn(tokenValidationContext("sub1"))
        val response = oAuth2AccessTokenService.getAccessToken(clientProperties)
        val request = server.takeRequest()
        val headers = request.headers
        val body = request.body.readUtf8()
        assertThat(headers["Content-Type"]).contains("application/x-www-form-urlencoded")
        assertThat(headers[AUTHORIZATION_HEADER]).isNotBlank
        val usernamePwd = Optional.ofNullable(headers[AUTHORIZATION_HEADER])
            .map { s: String -> s.split("Basic ").toTypedArray() }
            .filter { pair: Array<String> -> pair.size == 2 }
            .map { pair: Array<String> -> Base64.getDecoder().decode(pair[1]) }
            .map { bytes: ByteArray? -> String(bytes!!, StandardCharsets.UTF_8) }
            .orElse("")
        val auth = clientProperties.authentication
        assertThat(usernamePwd).isEqualTo(auth.clientId + ":" + auth.clientSecret)
        assertThat(body).contains(
            "grant_type=" + URLEncoder.encode(
                GrantType.JWT_BEARER.value,
                StandardCharsets.UTF_8))
        assertThat(body).contains(
            "scope=" + URLEncoder.encode(
                java.lang.String.join(" ", clientProperties.scope),
                StandardCharsets.UTF_8))
        assertThat(body).contains("requested_token_use=on_behalf_of")
        assertThat(body).contains("assertion=" + assertionResolver.token().orElse(null))
        assertThat(response).isNotNull
        assertThat(response?.accessToken).isNotBlank
        assertThat(response?.expiresAt).isGreaterThan(0)
        assertThat(response?.expiresIn).isGreaterThan(0)
    }

    @Test
    fun accessTokenUsingTokenExhange() {
        var clientProperties = clientConfigurationProperties.registration["example1-token" +
            "-exchange1"]
        assertThat(clientProperties).isNotNull
        clientProperties = clientProperties!!.toBuilder()
            .tokenEndpointUrl(tokenEndpointUrl)
            .build()
        server.enqueue(TestUtils.jsonResponse(TOKEN_RESPONSE))
        Mockito.`when`(tokenValidationContextHolder!!.getTokenValidationContext())
            .thenReturn(tokenValidationContext("sub1"))
        val response = oAuth2AccessTokenService.getAccessToken(clientProperties)
        val request = server.takeRequest()
        val headers = request.headers
        val body = request.body.readUtf8()
        assertThat(headers["Content-Type"]).contains("application/x-www-form-urlencoded")
        assertThat(body).contains(
            "grant_type=" + URLEncoder.encode(
                GrantType.TOKEN_EXCHANGE.value,
                StandardCharsets.UTF_8))
        assertThat(body).contains("subject_token=" + assertionResolver.token().orElse(null))
        assertThat(response).isNotNull
        assertThat(response?.accessToken).isNotBlank
        assertThat(response?.expiresAt).isGreaterThan(0)
        assertThat(response?.expiresIn).isGreaterThan(0)
    }

    @Test
    fun accessTokenClientCredentials() {
        var clientProperties = clientConfigurationProperties.registration["example1-clientcredentials1"]
        assertThat(clientProperties).isNotNull
        clientProperties = clientProperties!!.toBuilder()
            .tokenEndpointUrl(tokenEndpointUrl)
            .build()
        server.enqueue(TestUtils.jsonResponse(TOKEN_RESPONSE))
        val response = oAuth2AccessTokenService.getAccessToken(clientProperties)
        val request = server.takeRequest()
        val headers = request.headers
        val body = request.body.readUtf8()
        assertThat(headers["Content-Type"]).contains("application/x-www-form-urlencoded")
        assertThat(headers[AUTHORIZATION_HEADER]).isNotBlank
        val usernamePwd = Optional.ofNullable(headers["Authorization"])
            .map { s: String -> s.split("Basic ").toTypedArray() }
            .filter { pair: Array<String> -> pair.size == 2 }
            .map { pair: Array<String> -> Base64.getDecoder().decode(pair[1]) }
            .map { bytes: ByteArray? -> String(bytes!!, StandardCharsets.UTF_8) }
            .orElse("")
        val auth = clientProperties.authentication
        assertThat(usernamePwd).isEqualTo(auth.clientId + ":" + auth.clientSecret)
        assertThat(body).contains("grant_type=client_credentials")
        assertThat(body).contains(
            "scope=" + URLEncoder.encode(
                java.lang.String.join(" ", clientProperties.scope),
                StandardCharsets.UTF_8))
        assertThat(body).doesNotContain("requested_token_use=on_behalf_of")
        assertThat(body).doesNotContain("assertion=")
        assertThat(response).isNotNull
        assertThat(response?.accessToken).isNotBlank
        assertThat(response?.expiresAt).isGreaterThan(0)
        assertThat(response?.expiresIn).isGreaterThan(0)
    }

    companion object {
        private const val TOKEN_RESPONSE = "{\n" +
            "    \"token_type\": \"Bearer\",\n" +
            "    \"scope\": \"scope1 scope2\",\n" +
            "    \"expires_at\": 1568141495,\n" +
            "    \"ext_expires_in\": 3599,\n" +
            "    \"expires_in\": 3599,\n" +
            "    \"access_token\": \"<base64URL>\",\n" +
            "    \"refresh_token\": \"<base64URL>\"\n" +
            "}\n"
        private val log = LoggerFactory.getLogger(OAuth2AccessTokenServiceIntegrationTest::class.java)
        private fun tokenValidationContext(sub: String): TokenValidationContext {
            val expiry = LocalDateTime.now().atZone(ZoneId.systemDefault()).plusSeconds(60).toInstant()
            val jwt: JWT = PlainJWT(
                Builder()
                    .subject(sub)
                    .audience("thisapi")
                    .issuer("someIssuer")
                    .expirationTime(Date.from(expiry))
                    .claim("jti", UUID.randomUUID().toString())
                    .build())
            val map: MutableMap<String, JwtToken> = HashMap()
            map["issuer1"] = JwtToken(jwt.serialize())
            return TokenValidationContext(map)
        }
    }
}