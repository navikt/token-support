package no.nav.security.token.support.client.spring.oauth2
import no.nav.security.token.support.client.core.http.OAuth2HttpClient
import no.nav.security.token.support.client.core.http.OAuth2HttpHeaders
import no.nav.security.token.support.client.core.http.OAuth2HttpRequest
import no.nav.security.token.support.client.spring.reactive.oauth2.DefaultOAuth2WebClientHttpClient
import okhttp3.mockwebserver.MockWebServer
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.MockitoAnnotations
import org.springframework.http.client.reactive.ReactorClientHttpConnector
import org.springframework.web.reactive.function.client.WebClient
import reactor.netty.http.client.HttpClient
import java.io.IOException
import java.net.URI

internal class DefaultOAuth2ReactiveHttpClientTest {
    private lateinit var server: MockWebServer
    private var tokenEndpointUrl: URI? = null
    private lateinit var client: OAuth2HttpClient
    @BeforeEach
    @Throws(IOException::class)
    fun setup() {
        MockitoAnnotations.openMocks(this)
        server = MockWebServer()
        server.start()
        tokenEndpointUrl = server.url("/oauth2/token").toUri()
        client = DefaultOAuth2WebClientHttpClient(WebClient.builder().clientConnector(ReactorClientHttpConnector(HttpClient.create().wiretap(true))).build())
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
        val request = OAuth2HttpRequest.builder()
            .tokenEndpointUrl(tokenEndpointUrl)
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
        println("XXXXXXX " + body)
        assertThat(recordedRequest.headers["header1"]).isEqualTo("headervalue1")
        assertThat(recordedRequest.headers["header2"]).isEqualTo("headervalue2")
        assertThat(body).contains("param1=value1")
        assertThat(body).contains("param2=value2")
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
    }
}