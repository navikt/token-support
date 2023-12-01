package no.nav.security.token.support.client.core.oauth2

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import java.io.IOException
import java.net.URI
import okhttp3.mockwebserver.MockWebServer
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import no.nav.security.token.support.client.core.ClientAuthenticationProperties.Companion.builder
import no.nav.security.token.support.client.core.ClientProperties
import no.nav.security.token.support.client.core.ClientProperties.Companion.builder
import no.nav.security.token.support.client.core.ClientProperties.TokenExchangeProperties
import no.nav.security.token.support.client.core.OAuth2ClientException
import no.nav.security.token.support.client.core.OAuth2GrantType
import no.nav.security.token.support.client.core.OAuth2ParameterNames
import no.nav.security.token.support.client.core.TestUtils.assertPostMethodAndJsonHeaders
import no.nav.security.token.support.client.core.TestUtils.clientProperties
import no.nav.security.token.support.client.core.TestUtils.encodeValue
import no.nav.security.token.support.client.core.TestUtils.jsonResponse
import no.nav.security.token.support.client.core.TestUtils.jwt
import no.nav.security.token.support.client.core.http.SimpleOAuth2HttpClient

internal class TokenExchangeClientTest {

    private var tokenEndpointUrl : String? = null
    private var server : MockWebServer? = null
    private var tokenExchangeClient : TokenExchangeClient? = null
    private var subjectToken : String? = null
    @BeforeEach
    @Throws(IOException::class)
    fun setup() {
        server = MockWebServer()
        server!!.start()
        tokenEndpointUrl = server!!.url("/oauth2/v2/token").toString()
        tokenExchangeClient = TokenExchangeClient(SimpleOAuth2HttpClient())
        subjectToken = jwt("somesub").serialize()
    }

    @AfterEach
    @Throws(Exception::class)
    fun cleanup() {
        server!!.shutdown()
    }

    @Test
    fun tokenResponseWithPrivateKeyJwtAndExchangeProperties()  {
            server!!.enqueue(jsonResponse(TOKEN_RESPONSE))
            /*  ClientProperties clientProperties = tokenExchangeClientProperties(
            tokenEndpointUrl,
            TOKEN_EXCHANGE,
            "src/test/resources/jwk.json"
        )
            .toBuilder()
            .authentication(ClientAuthenticationProperties.builder("client",PRIVATE_KEY_JWT)
                .clientJwk("src/test/resources/jwk.json")
                .build())
            .build();
*/
            val clientProperties = builder(OAuth2GrantType.TOKEN_EXCHANGE, builder("client1", ClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .clientJwk("src/test/resources/jwk.json")
                .build())
                .tokenEndpointUrl(URI.create(tokenEndpointUrl))
                .tokenExchange(TokenExchangeProperties("audience")).build()
            val response = tokenExchangeClient!!.getTokenResponse(TokenExchangeGrantRequest(clientProperties, subjectToken!!))
            val recordedRequest = server!!.takeRequest()
            assertPostMethodAndJsonHeaders(recordedRequest)
            val body = recordedRequest.body.readUtf8()
            assertThatClientAuthMethodIsPrivateKeyJwt(body, clientProperties)
            assertThatRequestBodyContainsTokenExchangeFormParameters(body)
            assertThatResponseContainsAccessToken(response)
        }

    @Test
    fun tokenResponseError() {
            server!!.enqueue(jsonResponse(ERROR_RESPONSE).setResponseCode(400))
            Assertions.assertThatExceptionOfType(OAuth2ClientException::class.java)
                .isThrownBy {
                    tokenExchangeClient!!.getTokenResponse(TokenExchangeGrantRequest(clientProperties(
                        tokenEndpointUrl,
                        OAuth2GrantType.TOKEN_EXCHANGE
                                                                                                     ), subjectToken!!))
                }
        }

    private fun assertThatRequestBodyContainsTokenExchangeFormParameters(formParameters : String) {
        Assertions.assertThat(formParameters).contains(OAuth2ParameterNames.GRANT_TYPE + "=" + encodeValue(OAuth2GrantType.TOKEN_EXCHANGE.value()))
        Assertions.assertThat(formParameters).contains(OAuth2ParameterNames.AUDIENCE + "=" + "audience")
        Assertions.assertThat(formParameters).contains(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE + "=" + encodeValue("urn:ietf:params:oauth:token-type:jwt"))
        Assertions.assertThat(formParameters).contains(OAuth2ParameterNames.SUBJECT_TOKEN + "=" + subjectToken)
    }

    companion object {

        private const val TOKEN_RESPONSE = "{\n" +
            "    \"token_type\": \"Bearer\",\n" +
            "    \"scope\": \"scope1 scope2\",\n" +
            "    \"expires_at\": 1568141495,\n" +
            "    \"expires_in\": 3599,\n" +
            "    \"ext_expires_in\": 3599,\n" +
            "    \"access_token\": \"<base64URL>\"\n" +
            "}\n"
        private const val ERROR_RESPONSE = "{\"error\": \"some client error occurred\"}"
        private fun assertThatResponseContainsAccessToken(response : OAuth2AccessTokenResponse?) {
            Assertions.assertThat(response).isNotNull()
            Assertions.assertThat(response!!.accessToken).isNotBlank()
            Assertions.assertThat(response.expiresAt).isPositive()
            Assertions.assertThat(response.expiresIn).isPositive()
        }

        private fun assertThatClientAuthMethodIsPrivateKeyJwt(
            body : String,
            clientProperties : ClientProperties) {
            val auth = clientProperties.authentication
            Assertions.assertThat(auth.clientAuthMethod.value).isEqualTo("private_key_jwt")
            Assertions.assertThat(body).contains("client_id=" + encodeValue(auth.clientId))
            Assertions.assertThat(body).contains("client_assertion_type=" + encodeValue(
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"))
            Assertions.assertThat(body).contains("client_assertion=" + "ey")
        }
    }
}