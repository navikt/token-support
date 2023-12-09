package no.nav.security.token.support.client.core.oauth2

import com.nimbusds.oauth2.sdk.GrantType
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import java.io.IOException
import java.net.URI
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
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

internal class ClientCredentialsTokenClientTest {

    private var tokenEndpointUrl : String? = null
    private var server : MockWebServer? = null
    private var client : ClientCredentialsTokenClient? = null
    @BeforeEach
    @Throws(IOException::class)
    fun setup() {
        server = MockWebServer()
        server!!.start()
        tokenEndpointUrl = server!!.url("/oauth2/v2/token").toString()
        client = ClientCredentialsTokenClient(SimpleOAuth2HttpClient())
    }

    @AfterEach
    @Throws(Exception::class)
    fun cleanup() {
        server!!.shutdown()
    }

    @Test
    fun tokenResponseWithDefaultClientAuthMethod()  {
            server!!.enqueue(jsonResponse(TOKEN_RESPONSE))
            val clientProperties = clientProperties(tokenEndpointUrl, GrantType.CLIENT_CREDENTIALS)
            val response = client!!.getTokenResponse(ClientCredentialsGrantRequest(clientProperties))
            val recordedRequest = server!!.takeRequest()
            assertPostMethodAndJsonHeaders(recordedRequest)
            assertThatClientAuthMethodIsClientSecretBasic(recordedRequest, clientProperties)
            val body = recordedRequest.body.readUtf8()
            assertThatRequestBodyContainsFormParameters(body)
            assertThatResponseContainsAccessToken(response)
        }

    @Test
    fun  tokenResponseWithClientSecretBasic() {
            server!!.enqueue(jsonResponse(TOKEN_RESPONSE))
            val clientProperties = clientProperties(tokenEndpointUrl, GrantType.CLIENT_CREDENTIALS)
            val response = client!!.getTokenResponse(ClientCredentialsGrantRequest(clientProperties))
            val recordedRequest = server!!.takeRequest()
            assertPostMethodAndJsonHeaders(recordedRequest)
            assertThatClientAuthMethodIsClientSecretBasic(recordedRequest, clientProperties)
            val body = recordedRequest.body.readUtf8()
            assertThatRequestBodyContainsFormParameters(body)
            assertThatResponseContainsAccessToken(response)
        }

    @Test
    fun  tokenResponseWithClientSecretPost(){
            server!!.enqueue(jsonResponse(TOKEN_RESPONSE))
            val clientProperties = builder(GrantType.CLIENT_CREDENTIALS, builder("client", ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .clientSecret("secret").build())
                .tokenEndpointUrl(URI.create(tokenEndpointUrl))
                .scope(listOf("scope1", "scope2"))
                .build()
            val response = client!!.getTokenResponse(ClientCredentialsGrantRequest(clientProperties))
            val recordedRequest = server!!.takeRequest()
            assertPostMethodAndJsonHeaders(recordedRequest)
            val body = recordedRequest.body.readUtf8()
            assertThatClientAuthMethodIsClientSecretPost(body, clientProperties)
            assertThatRequestBodyContainsFormParameters(body)
            assertThatResponseContainsAccessToken(response)
        }

    @Test
    fun tokenResponseWithPrivateKeyJwt()
         {
            server!!.enqueue(jsonResponse(TOKEN_RESPONSE))
            /*    ClientProperties clientProperties = clientProperties(tokenEndpointUrl, CLIENT_CREDENTIALS)
            .toBuilder()
            .authentication(ClientAuthenticationProperties.builder("client",PRIVATE_KEY_JWT)
                .clientJwk("src/test/resources/jwk.json")
                .build())
            .build();
*/
            val clientProperties = builder(GrantType.CLIENT_CREDENTIALS, builder("client", ClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .clientSecret("secret")
                .clientJwk("src/test/resources/jwk.json")
                .build())
                .tokenEndpointUrl(URI.create(tokenEndpointUrl))
                .scope(listOf("scope1", "scope2"))
                .build()
            val response = client!!.getTokenResponse(ClientCredentialsGrantRequest(clientProperties))
            val recordedRequest = server!!.takeRequest()
            assertPostMethodAndJsonHeaders(recordedRequest)
            val body = recordedRequest.body.readUtf8()
            assertThatClientAuthMethodIsPrivateKeyJwt(body, clientProperties)
            assertThatRequestBodyContainsFormParameters(body)
            assertThatResponseContainsAccessToken(response)
        }

    @Test
    fun tokenResponseError() {
            server!!.enqueue(jsonResponse(ERROR_RESPONSE).setResponseCode(400))
            Assertions.assertThatExceptionOfType(OAuth2ClientException::class.java)
                .isThrownBy {
                    client!!.getTokenResponse(ClientCredentialsGrantRequest(clientProperties(
                        tokenEndpointUrl,
                        GrantType.CLIENT_CREDENTIALS
                                                                                            )))
                }
        }

    companion object {

        private const val TOKEN_RESPONSE = "{\n" +
            "    \"token_type\": \"Bearer\",\n" +
            "    \"scope\": \"scope1 scope2\",\n" +
            "    \"expires_at\": 1568141495,\n" +
            "    \"expires_in\": 3599,\n" +
            "    \"ext_expires_in\": 3599,\n" +
            "    \"access_token\": \"<base64URL>\",\n" +
            "    \"refresh_token\": \"<base64URL>\"\n" +
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

        private fun assertThatClientAuthMethodIsClientSecretPost(
            body : String,
            clientProperties : ClientProperties) {
            val auth = clientProperties.authentication
            Assertions.assertThat(auth.clientAuthMethod.value).isEqualTo("client_secret_post")
            Assertions.assertThat(body).contains("client_id=" + encodeValue(auth.clientId))
            Assertions.assertThat(body).contains("client_secret=" + encodeValue(auth.clientSecret))
        }

        private fun assertThatClientAuthMethodIsClientSecretBasic(recordedRequest : RecordedRequest,
                                                                  clientProperties : ClientProperties) {
            val auth = clientProperties.authentication
            Assertions.assertThat(auth.clientAuthMethod.value).isEqualTo("client_secret_basic")
            Assertions.assertThat(recordedRequest.headers["Authorization"]).isNotBlank()
            val usernamePwd = decodeBasicAuth(recordedRequest)
            Assertions.assertThat(usernamePwd).isEqualTo(auth.clientId + ":" + auth.clientSecret)
        }

        private fun assertThatRequestBodyContainsFormParameters(formParameters : String) {
            Assertions.assertThat(formParameters).contains("grant_type=client_credentials")
            Assertions.assertThat(formParameters).contains("scope=scope1+scope2")
        }
    }
}