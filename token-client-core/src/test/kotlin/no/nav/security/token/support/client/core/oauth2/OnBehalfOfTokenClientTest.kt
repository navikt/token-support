package no.nav.security.token.support.client.core.oauth2

import com.nimbusds.oauth2.sdk.GrantType.JWT_BEARER
import java.net.URLEncoder
import java.nio.charset.StandardCharsets.UTF_8
import okhttp3.mockwebserver.MockWebServer
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatExceptionOfType
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import no.nav.security.token.support.client.core.OAuth2ClientException
import no.nav.security.token.support.client.core.TestUtils.assertPostMethodAndJsonHeaders
import no.nav.security.token.support.client.core.TestUtils.clientProperties
import no.nav.security.token.support.client.core.TestUtils.jsonResponse
import no.nav.security.token.support.client.core.TestUtils.jwt
import no.nav.security.token.support.client.core.http.SimpleOAuth2HttpClient

internal class OnBehalfOfTokenClientTest {

    private lateinit var onBehalfOfTokenResponseClient : OnBehalfOfTokenClient
    private lateinit var tokenEndpointUrl : String
    private lateinit var server : MockWebServer
    @BeforeEach
    fun setup() {
        server = MockWebServer()
        server.start()
        tokenEndpointUrl = server.url(TOKEN_ENDPOINT).toString()
        onBehalfOfTokenResponseClient = OnBehalfOfTokenClient(SimpleOAuth2HttpClient())
    }

    @AfterEach
    fun teardown() {
        server.shutdown()
    }

    @Test
    fun tokenResponse()  {
            server.enqueue(jsonResponse(TOKEN_RESPONSE))
            val assertion = jwt("sub1").serialize()
            val clientProperties = clientProperties(tokenEndpointUrl, JWT_BEARER)
            val oAuth2OnBehalfOfGrantRequest = OnBehalfOfGrantRequest(clientProperties, assertion)
            val response = onBehalfOfTokenResponseClient.getTokenResponse(oAuth2OnBehalfOfGrantRequest)
            val recordedRequest = server.takeRequest()
            assertPostMethodAndJsonHeaders(recordedRequest)
            val formParameters = recordedRequest.body.readUtf8()
            assertThat(formParameters)
                .contains("grant_type=${URLEncoder.encode(JWT_BEARER.value, UTF_8)}")
                .contains("scope=scope1+scope2")
                .contains("requested_token_use=on_behalf_of")
                .contains("assertion=$assertion")
            assertThat(response).isNotNull()
            assertThat(response?.accessToken).isNotBlank()
            assertThat(response?.expiresAt).isPositive()
            assertThat(response?.expiresIn).isPositive()
        }

    @Test
    fun  tokenResponseWithError() {
            server.enqueue(jsonResponse(ERROR_RESPONSE).setResponseCode(400))
            val assertion = jwt("sub1").serialize()
            val clientProperties = clientProperties(tokenEndpointUrl, JWT_BEARER)
            val oAuth2OnBehalfOfGrantRequest = OnBehalfOfGrantRequest(clientProperties, assertion)
            assertThrows<OAuth2ClientException> {
                val res = onBehalfOfTokenResponseClient.getTokenResponse(oAuth2OnBehalfOfGrantRequest)
                println(res)
            }
    }

    companion object {

        private val TOKEN_RESPONSE = """{
             "token_type": "Bearer",
             "scope": "scope1 scope2",
             "expires_at": 1568141495,
             "ext_expires_in": 3599,
             "expires_in": 3599,
             "access_token": "<base64URL>",
             "refresh_token": "<base64URL>"
        }
        """.trimIndent()
        private const val ERROR_RESPONSE = """{"error": "some client error occurred"}"""
        private const val TOKEN_ENDPOINT = "/oauth2/v2.0/token"
    }
}