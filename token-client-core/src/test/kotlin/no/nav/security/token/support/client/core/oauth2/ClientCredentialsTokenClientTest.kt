package no.nav.security.token.support.client.core.oauth2

import com.nimbusds.oauth2.sdk.GrantType.CLIENT_CREDENTIALS
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import java.net.URI
import no.nav.security.token.support.client.core.ClientAuthenticationProperties.Companion.builder
import no.nav.security.token.support.client.core.ClientProperties
import no.nav.security.token.support.client.core.ClientProperties.Companion.builder
import no.nav.security.token.support.client.core.OAuth2ClientException
import no.nav.security.token.support.client.core.TestUtils.assertPostMethodAndJsonHeaders
import no.nav.security.token.support.client.core.TestUtils.clientProperties
import no.nav.security.token.support.client.core.TestUtils.decodeBasicAuth
import no.nav.security.token.support.client.core.TestUtils.encodeValue
import no.nav.security.token.support.client.core.TestUtils.jsonResponse
import no.nav.security.token.support.client.core.http.SimpleOAuth2HttpClient
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

internal class ClientCredentialsTokenClientTest {

    private lateinit var tokenEndpointUrl : String
    private lateinit var server : MockWebServer
    private lateinit var client : ClientCredentialsTokenClient
    @BeforeEach
    fun setup() {
        server = MockWebServer()
        server.start()
        tokenEndpointUrl = server.url("/oauth2/v2/token").toString()
        client = ClientCredentialsTokenClient(SimpleOAuth2HttpClient())
    }

    @AfterEach
    fun cleanup() {
        server.shutdown()
    }

    @Test
    fun tokenResponseWithDefaultClientAuthMethod()  {
            server.enqueue(jsonResponse(TOKEN_RESPONSE))
            val clientProperties = clientProperties(tokenEndpointUrl, CLIENT_CREDENTIALS)
            val response = client.getTokenResponse(ClientCredentialsGrantRequest(clientProperties))
            val recordedRequest = server.takeRequest()
            assertPostMethodAndJsonHeaders(recordedRequest)
            assertThatClientAuthMethodIsClientSecretBasic(recordedRequest, clientProperties)
            assertThatRequestBodyContainsFormParameters(recordedRequest.body.readUtf8())
            assertThatResponseContainsAccessToken(response)
        }

    @Test
    fun  tokenResponseWithClientSecretBasic() {
            server.enqueue(jsonResponse(TOKEN_RESPONSE))
            val clientProperties = clientProperties(tokenEndpointUrl, CLIENT_CREDENTIALS)
            val response = client.getTokenResponse(ClientCredentialsGrantRequest(clientProperties))
            val recordedRequest = server.takeRequest()
            assertPostMethodAndJsonHeaders(recordedRequest)
            assertThatClientAuthMethodIsClientSecretBasic(recordedRequest, clientProperties)
            assertThatRequestBodyContainsFormParameters(recordedRequest.body.readUtf8())
            assertThatResponseContainsAccessToken(response)
        }

    @Test
    fun  tokenResponseWithClientSecretPost() {
            server.enqueue(jsonResponse(TOKEN_RESPONSE))
            val clientProperties = builder(CLIENT_CREDENTIALS, builder("client", ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .clientSecret("secret").build())
                .tokenEndpointUrl(URI.create(tokenEndpointUrl))
                .scope(listOf("scope1", "scope2"))
                .build()
            val response = client.getTokenResponse(ClientCredentialsGrantRequest(clientProperties))
            val recordedRequest = server.takeRequest()
            assertPostMethodAndJsonHeaders(recordedRequest)
            val body = recordedRequest.body.readUtf8()
            assertThatClientAuthMethodIsClientSecretPost(body, clientProperties)
            assertThatRequestBodyContainsFormParameters(body)
            assertThatResponseContainsAccessToken(response)
        }

    @Test
    fun tokenResponseWithPrivateKeyJwt() {
            server.enqueue(jsonResponse(TOKEN_RESPONSE))
            val clientProperties = builder(CLIENT_CREDENTIALS, builder("client", ClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .clientSecret("secret")
                .clientJwk("src/test/resources/jwk.json")
                .build())
                .tokenEndpointUrl(URI.create(tokenEndpointUrl))
                .scope(listOf("scope1", "scope2"))
                .build()
            val response = client.getTokenResponse(ClientCredentialsGrantRequest(clientProperties))
            val recordedRequest = server.takeRequest()
            assertPostMethodAndJsonHeaders(recordedRequest)
            val body = recordedRequest.body.readUtf8()
            assertThatClientAuthMethodIsPrivateKeyJwt(body, clientProperties)
            assertThatRequestBodyContainsFormParameters(body)
            assertThatResponseContainsAccessToken(response)
        }

    @Test
    fun tokenResponseError() {
        server.enqueue(jsonResponse(ERROR_RESPONSE).setResponseCode(400))
        assertThrows<OAuth2ClientException> {
            client.getTokenResponse(ClientCredentialsGrantRequest(clientProperties(tokenEndpointUrl, CLIENT_CREDENTIALS)))
        }
    }

    companion object {

        private const val TOKEN_RESPONSE = """{
             "token_type": "Bearer",
             "scope": "scope1 scope2",
             "expires_at": 1568141495,
             "expires_in": 3599,
             "ext_expires_in": 3599,
             "access_token": "<base64URL>",
             "refresh_token": "<base64URL>"
       }"""
        private const val ERROR_RESPONSE = """{"error": "some client error occurred"}"""
        private fun assertThatResponseContainsAccessToken(response : OAuth2AccessTokenResponse?) {
            assertThat(response).isNotNull()
            assertThat(response!!.accessToken).isNotBlank()
            assertThat(response.expiresAt).isPositive()
            assertThat(response.expiresIn).isPositive()
        }

        private fun assertThatClientAuthMethodIsPrivateKeyJwt(body : String, clientProperties : ClientProperties) {
            val auth = clientProperties.authentication
            assertThat(auth.clientAuthMethod.value).isEqualTo("private_key_jwt")
            assertThat(body).contains("client_id=" + encodeValue(auth.clientId))
            assertThat(body).contains("client_assertion_type=" + encodeValue("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"))
            assertThat(body).contains("client_assertion=" + "ey")
        }

        private fun assertThatClientAuthMethodIsClientSecretPost(body : String, clientProperties : ClientProperties) {
            val auth = clientProperties.authentication
            assertThat(auth.clientAuthMethod.value).isEqualTo("client_secret_post")
            assertThat(body).contains("client_id=" + encodeValue(auth.clientId))
            assertThat(body).contains("client_secret=" + encodeValue(auth.clientSecret))
        }

        private fun assertThatClientAuthMethodIsClientSecretBasic(recordedRequest : RecordedRequest, clientProperties : ClientProperties) {
            val auth = clientProperties.authentication
            assertThat(auth.clientAuthMethod.value).isEqualTo("client_secret_basic")
            assertThat(recordedRequest.headers["Authorization"]).isNotBlank()
            val usernamePwd = decodeBasicAuth(recordedRequest)
            assertThat(usernamePwd).isEqualTo(auth.clientId + ":" + auth.clientSecret)
        }

        private fun assertThatRequestBodyContainsFormParameters(formParameters : String) {
            assertThat(formParameters).contains("grant_type=client_credentials")
            assertThat(formParameters).contains("scope=scope1+scope2")
        }
    }
}