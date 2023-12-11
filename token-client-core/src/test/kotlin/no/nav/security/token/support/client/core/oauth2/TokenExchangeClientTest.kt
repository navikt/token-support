package no.nav.security.token.support.client.core.oauth2

import com.nimbusds.oauth2.sdk.GrantType
import com.nimbusds.oauth2.sdk.GrantType.*
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import java.io.IOException
import java.net.URI
import okhttp3.mockwebserver.MockWebServer
import org.assertj.core.api.Assertions
import org.assertj.core.api.Assertions.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import no.nav.security.token.support.client.core.ClientAuthenticationProperties.Companion.builder
import no.nav.security.token.support.client.core.ClientProperties
import no.nav.security.token.support.client.core.ClientProperties.Companion.builder
import no.nav.security.token.support.client.core.ClientProperties.TokenExchangeProperties
import no.nav.security.token.support.client.core.OAuth2ClientException
import no.nav.security.token.support.client.core.OAuth2ParameterNames
import no.nav.security.token.support.client.core.OAuth2ParameterNames.GRANT_TYPE
import no.nav.security.token.support.client.core.OAuth2ParameterNames.SUBJECT_TOKEN
import no.nav.security.token.support.client.core.OAuth2ParameterNames.SUBJECT_TOKEN_TYPE
import no.nav.security.token.support.client.core.TestUtils.assertPostMethodAndJsonHeaders
import no.nav.security.token.support.client.core.TestUtils.clientProperties
import no.nav.security.token.support.client.core.TestUtils.encodeValue
import no.nav.security.token.support.client.core.TestUtils.jsonResponse
import no.nav.security.token.support.client.core.TestUtils.jwt
import no.nav.security.token.support.client.core.http.SimpleOAuth2HttpClient

internal class TokenExchangeClientTest {

    private  lateinit var tokenEndpointUrl : String
    private lateinit var server : MockWebServer
    private lateinit var tokenExchangeClient : TokenExchangeClient
    private var subjectToken = jwt("somesub").serialize()
    @BeforeEach
    fun setup() {
        server = MockWebServer()
        server.start()
        tokenEndpointUrl = server.url("/oauth2/v2/token").toString()
        tokenExchangeClient = TokenExchangeClient(SimpleOAuth2HttpClient())
    }

    @AfterEach
    fun cleanup() {
        server.shutdown()
    }

    @Test
    fun tokenResponseWithPrivateKeyJwtAndExchangeProperties()  {
            server.enqueue(jsonResponse(TOKEN_RESPONSE))
            val clientProperties = builder(TOKEN_EXCHANGE, builder("client1", ClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .clientJwk("src/test/resources/jwk.json")
                .build())
                .tokenEndpointUrl(URI.create(tokenEndpointUrl))
                .tokenExchange(TokenExchangeProperties("audience")).build()

            val response = tokenExchangeClient.getTokenResponse(TokenExchangeGrantRequest(clientProperties, subjectToken!!))
            val recordedRequest = server.takeRequest()
            assertPostMethodAndJsonHeaders(recordedRequest)
            val body = recordedRequest.body.readUtf8()
            assertThatClientAuthMethodIsPrivateKeyJwt(body, clientProperties)
            assertThatRequestBodyContainsTokenExchangeFormParameters(body)
            assertThatResponseContainsAccessToken(response)
        }

    @Test
    fun tokenResponseError() {
        server.enqueue(jsonResponse(ERROR_RESPONSE).setResponseCode(400))
        assertThrows<OAuth2ClientException>{
            tokenExchangeClient.getTokenResponse(TokenExchangeGrantRequest(clientProperties(
                tokenEndpointUrl,
                TOKEN_EXCHANGE), subjectToken!!))
        }
    }

    private fun assertThatRequestBodyContainsTokenExchangeFormParameters(formParameters : String) {
        assertThat(formParameters).contains("$GRANT_TYPE=${encodeValue(TOKEN_EXCHANGE.value)}")
        assertThat(formParameters).contains("${OAuth2ParameterNames.AUDIENCE}=audience")
        assertThat(formParameters).contains("$SUBJECT_TOKEN_TYPE=${encodeValue("urn:ietf:params:oauth:token-type:jwt")}")
        assertThat(formParameters).contains("$SUBJECT_TOKEN=$subjectToken")
    }

    companion object {

        private const val TOKEN_RESPONSE = """{
           "token_type": "Bearer",
           "scope": "scope1 scope2",
           "expires_at": 1568141495,
           "expires_in": 3599,
           "ext_expires_in": 3599,
           "access_token": "<base64URL>"
         }"""
        private const val ERROR_RESPONSE = """{"error": "some client error occurred"}"""
        private fun assertThatResponseContainsAccessToken(response : OAuth2AccessTokenResponse?) {
            assertThat(response).isNotNull()
            assertThat(response!!.accessToken).isNotBlank()
            assertThat(response.expiresAt).isPositive()
            assertThat(response.expiresIn).isPositive()
        }

        private fun assertThatClientAuthMethodIsPrivateKeyJwt(
            body : String,
            clientProperties : ClientProperties) {
            val auth = clientProperties.authentication
            assertThat(auth.clientAuthMethod.value).isEqualTo("private_key_jwt")
            assertThat(body).contains("client_id=${encodeValue(auth.clientId)}")
            assertThat(body).contains("client_assertion_type=${encodeValue("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")}")
            assertThat(body).contains("client_assertion=ey")
        }
    }
}