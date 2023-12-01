package no.nav.security.token.support.client.core.oauth2

import java.io.IOException
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import okhttp3.mockwebserver.MockWebServer
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.MockitoAnnotations
import no.nav.security.token.support.client.core.OAuth2ClientException
import no.nav.security.token.support.client.core.OAuth2GrantType
import no.nav.security.token.support.client.core.TestUtils.assertPostMethodAndJsonHeaders
import no.nav.security.token.support.client.core.TestUtils.clientProperties
import no.nav.security.token.support.client.core.TestUtils.jsonResponse
import no.nav.security.token.support.client.core.TestUtils.jwt
import no.nav.security.token.support.client.core.http.SimpleOAuth2HttpClient

internal class OnBehalfOfTokenClientTest {

    private var onBehalfOfTokenResponseClient : OnBehalfOfTokenClient? = null
    private var tokenEndpointUrl : String? = null
    private var server : MockWebServer? = null
    @BeforeEach
    @Throws(IOException::class)
    fun setup() {
        MockitoAnnotations.initMocks(this)
        server = MockWebServer()
        server!!.start()
        tokenEndpointUrl = server!!.url(TOKEN_ENDPOINT).toString()
        onBehalfOfTokenResponseClient = OnBehalfOfTokenClient(SimpleOAuth2HttpClient())
    }

    @AfterEach
    @Throws(IOException::class)
    fun teardown() {
        server!!.shutdown()
    }

    @Test
    fun tokenResponse()  {
            server!!.enqueue(jsonResponse(TOKEN_RESPONSE))
            val assertion = jwt("sub1").serialize()
            val clientProperties = clientProperties(tokenEndpointUrl, OAuth2GrantType.JWT_BEARER)
            val oAuth2OnBehalfOfGrantRequest = OnBehalfOfGrantRequest(clientProperties, assertion)
            val response = onBehalfOfTokenResponseClient!!.getTokenResponse(oAuth2OnBehalfOfGrantRequest)
            val recordedRequest = server!!.takeRequest()
            assertPostMethodAndJsonHeaders(recordedRequest)
            val formParameters = recordedRequest.body.readUtf8()
            Assertions.assertThat(formParameters).contains("grant_type=" + URLEncoder.encode(OAuth2GrantType.JWT_BEARER.value(),
                StandardCharsets.UTF_8))
                .contains("scope=scope1+scope2")
                .contains("requested_token_use=on_behalf_of")
                .contains("assertion=$assertion")
            Assertions.assertThat(response).isNotNull()
            Assertions.assertThat(response!!.accessToken).isNotBlank()
            Assertions.assertThat(response.expiresAt).isPositive()
            Assertions.assertThat(response.expiresIn).isPositive()
        }

    @Test
    fun  tokenResponseWithError() {
            server!!.enqueue(jsonResponse(ERROR_RESPONSE).setResponseCode(400))
            val assertion = jwt("sub1").serialize()
            val clientProperties = clientProperties(tokenEndpointUrl, OAuth2GrantType.JWT_BEARER)
            val oAuth2OnBehalfOfGrantRequest = OnBehalfOfGrantRequest(clientProperties, assertion)
            Assertions.assertThatExceptionOfType(OAuth2ClientException::class.java)
                .isThrownBy { onBehalfOfTokenResponseClient!!.getTokenResponse(oAuth2OnBehalfOfGrantRequest) }
                .withMessageContaining(ERROR_RESPONSE)
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
        private const val ERROR_RESPONSE = "{\"error\": \"some client error occurred\"}"
        private const val TOKEN_ENDPOINT = "/oauth2/v2.0/token"
    }
}