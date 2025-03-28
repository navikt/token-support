package no.nav.security.token.support.client.spring.oauth2
import java.io.IOException
import java.net.URI
import no.nav.security.token.support.client.core.http.OAuth2HttpHeaders
import no.nav.security.token.support.client.core.http.OAuth2HttpRequest
import okhttp3.mockwebserver.MockWebServer
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.MockitoAnnotations
import org.springframework.web.client.RestClient

internal class DefaultOAuth2HttpClientTest {
    private lateinit var server: MockWebServer
    private lateinit var tokenEndpointUrl: URI
    private lateinit var client: DefaultOAuth2HttpClient
    @BeforeEach
    @Throws(IOException::class)
    fun setup() {
        MockitoAnnotations.openMocks(this)
        server = MockWebServer()
        server.start()
        tokenEndpointUrl = server.url("/oauth2/token").toUri()
        client = DefaultOAuth2HttpClient()
    }

    @AfterEach
    @Throws(IOException::class)
    fun teardown() {
        server.shutdown()
    }

    @Test
    @Throws(InterruptedException::class)
    fun testPostAllHeadersAndFormParametersShouldBePresent() {
        server.enqueue(TestUtils.jsonResponse(TOKEN_RESPONSE))
        val request = OAuth2HttpRequest.builder(tokenEndpointUrl)
            .formParameter("param1", "value1")
            .formParameter("param2", "value2")
            .oAuth2HttpHeaders(
                    OAuth2HttpHeaders.builder()
                        .header("header1", "headervalue1")
                        .header("header2", "headervalue2")
                        .build())
            .build()
        client.post(request)
        val recordedRequest = server.takeRequest()
        val body = recordedRequest.body.readUtf8()
        assertThat(recordedRequest.headers["header1"]).isEqualTo("headervalue1")
        assertThat(recordedRequest.headers["header2"]).isEqualTo("headervalue2")
        assertThat(body)
            .contains("param1=value1")
            .contains("param2=value2")
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
    }
}