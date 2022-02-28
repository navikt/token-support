package no.nav.security.token.support.client.spring.oauth2

import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTClaimsSet.Builder
import com.nimbusds.jwt.PlainJWT
import no.nav.security.token.support.client.core.OAuth2GrantType
import no.nav.security.token.support.client.core.context.JwtBearerTokenResolver
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenService
import no.nav.security.token.support.client.spring.ClientConfigurationProperties
import no.nav.security.token.support.core.context.TokenValidationContext
import no.nav.security.token.support.core.context.TokenValidationContextHolder
import no.nav.security.token.support.core.jwt.JwtToken
import okhttp3.mockwebserver.MockWebServer
import org.assertj.core.api.Assertions
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
import java.util.*

@SpringBootTest(classes = [ConfigurationWithCacheEnabledTrue::class])
@ActiveProfiles("test")
internal class OAuth2AccessTokenServiceIntegrationTest {
    @MockBean
    private val tokenValidationContextHolder: TokenValidationContextHolder? = null

    @Autowired
    private lateinit var  oAuth2AccessTokenService: OAuth2AccessTokenService

    @Autowired
    private lateinit var  clientConfigurationProperties: ClientConfigurationProperties

    @Autowired
    private lateinit var  assertionResolver: JwtBearerTokenResolver
    private var server: MockWebServer? = null
    private var tokenEndpointUrl: URI? = null
    @BeforeEach
    @Throws(IOException::class)
    fun setup() {
        MockitoAnnotations.openMocks(this)
        server = MockWebServer()
        server!!.start()
        tokenEndpointUrl = server!!.url("/oauth2/token").toUri()
    }

    @AfterEach
    @Throws(IOException::class)
    fun teardown() {
        server!!.shutdown()
    }

    @get:Throws(InterruptedException::class)
    @get:Test
    val accessTokenOnBehalfOf: Unit
        get() {
            var clientProperties = clientConfigurationProperties.registration["example1-onbehalfof"]
            Assertions.assertThat(clientProperties).isNotNull
            clientProperties = clientProperties!!.toBuilder()
                .tokenEndpointUrl(tokenEndpointUrl)
                .build()
            server!!.enqueue(TestUtils.jsonResponse(TOKEN_RESPONSE))
            Mockito.`when`(tokenValidationContextHolder!!.tokenValidationContext)
                .thenReturn(tokenValidationContext("sub1"))
            val response = oAuth2AccessTokenService.getAccessToken(clientProperties)
            val request = server!!.takeRequest()
            val headers = request.headers
            val body = request.body.readUtf8()
            Assertions.assertThat(headers["Content-Type"]).contains("application/x-www-form-urlencoded")
            Assertions.assertThat(headers["Authorization"]).isNotBlank
            val usernamePwd = Optional.ofNullable(headers["Authorization"])
                .map { s: String -> s.split("Basic ").toTypedArray() }
                .filter { pair: Array<String> -> pair.size == 2 }
                .map { pair: Array<String> -> Base64.getDecoder().decode(pair[1]) }
                .map { bytes: ByteArray? -> String(bytes!!, StandardCharsets.UTF_8) }
                .orElse("")
            val auth = clientProperties.authentication
            Assertions.assertThat(usernamePwd).isEqualTo(auth.clientId + ":" + auth.clientSecret)
            Assertions.assertThat(body).contains(
                    "grant_type=" + URLEncoder.encode(
                            OAuth2GrantType.JWT_BEARER.value,
                            StandardCharsets.UTF_8))
            Assertions.assertThat(body).contains(
                    "scope=" + URLEncoder.encode(
                            java.lang.String.join(" ", clientProperties.scope),
                            StandardCharsets.UTF_8))
            Assertions.assertThat(body).contains("requested_token_use=on_behalf_of")
            Assertions.assertThat(body).contains("assertion=" + assertionResolver.token().orElse(null))
            Assertions.assertThat(response).isNotNull
            Assertions.assertThat(response.accessToken).isNotBlank
            Assertions.assertThat(response.expiresAt).isGreaterThan(0)
            Assertions.assertThat(response.expiresIn).isGreaterThan(0)
        }

    @get:Throws(InterruptedException::class)
    @get:Test
    val accessTokenUsingTokenExhange: Unit
        get() {
            var clientProperties = clientConfigurationProperties.registration["example1-token" +
                    "-exchange1"]
            Assertions.assertThat(clientProperties).isNotNull
            clientProperties = clientProperties!!.toBuilder()
                .tokenEndpointUrl(tokenEndpointUrl)
                .build()
            server!!.enqueue(TestUtils.jsonResponse(TOKEN_RESPONSE))
            Mockito.`when`(tokenValidationContextHolder!!.tokenValidationContext)
                .thenReturn(tokenValidationContext("sub1"))
            val response = oAuth2AccessTokenService.getAccessToken(clientProperties)
            val request = server!!.takeRequest()
            val headers = request.headers
            val body = request.body.readUtf8()
            Assertions.assertThat(headers["Content-Type"]).contains("application/x-www-form-urlencoded")
            Assertions.assertThat(body).contains(
                    "grant_type=" + URLEncoder.encode(
                            OAuth2GrantType.TOKEN_EXCHANGE.value,
                            StandardCharsets.UTF_8))
            Assertions.assertThat(body).contains("subject_token=" + assertionResolver.token().orElse(null))
            Assertions.assertThat(response).isNotNull
            Assertions.assertThat(response.accessToken).isNotBlank
            Assertions.assertThat(response.expiresAt).isGreaterThan(0)
            Assertions.assertThat(response.expiresIn).isGreaterThan(0)
        }

    @get:Throws(InterruptedException::class)
    @get:Test
    val accessTokenClientCredentials: Unit
        get() {
            var clientProperties = clientConfigurationProperties.registration["example1-clientcredentials1"]
            Assertions.assertThat(clientProperties).isNotNull
            clientProperties = clientProperties!!.toBuilder()
                .tokenEndpointUrl(tokenEndpointUrl)
                .build()
            server!!.enqueue(TestUtils.jsonResponse(TOKEN_RESPONSE))
            val response = oAuth2AccessTokenService.getAccessToken(clientProperties)
            val request = server!!.takeRequest()
            val headers = request.headers
            val body = request.body.readUtf8()
            Assertions.assertThat(headers["Content-Type"]).contains("application/x-www-form-urlencoded")
            Assertions.assertThat(headers["Authorization"]).isNotBlank
            val usernamePwd = Optional.ofNullable(headers["Authorization"])
                .map { s: String -> s.split("Basic ").toTypedArray() }
                .filter { pair: Array<String> -> pair.size == 2 }
                .map { pair: Array<String> -> Base64.getDecoder().decode(pair[1]) }
                .map { bytes: ByteArray? -> String(bytes!!, StandardCharsets.UTF_8) }
                .orElse("")
            val auth = clientProperties.authentication
            Assertions.assertThat(usernamePwd).isEqualTo(auth.clientId + ":" + auth.clientSecret)
            Assertions.assertThat(body).contains("grant_type=client_credentials")
            Assertions.assertThat(body).contains(
                    "scope=" + URLEncoder.encode(
                            java.lang.String.join(" ", clientProperties.scope),
                            StandardCharsets.UTF_8))
            Assertions.assertThat(body).doesNotContain("requested_token_use=on_behalf_of")
            Assertions.assertThat(body).doesNotContain("assertion=")
            Assertions.assertThat(response).isNotNull
            Assertions.assertThat(response.accessToken).isNotBlank
            Assertions.assertThat(response.expiresAt).isGreaterThan(0)
            Assertions.assertThat(response.expiresIn).isGreaterThan(0)
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