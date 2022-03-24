package no.nav.security.token.support.client.spring.oauth2

import no.nav.security.token.support.client.core.context.JwtBearerTokenResolver
import no.nav.security.token.support.client.core.http.OAuth2HttpClient
import no.nav.security.token.support.client.core.http.OAuth2HttpHeaders
import no.nav.security.token.support.client.core.http.OAuth2HttpRequest
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenService
import no.nav.security.token.support.client.spring.reactive.oauth2.DefaultOAuth2WebClientHttpClient
import no.nav.security.token.support.client.spring.reactive.oauth2.OAuth2ReactiveClientAutoConfiguration
import okhttp3.mockwebserver.MockWebServer
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.MockitoAnnotations
import org.springframework.boot.autoconfigure.AutoConfigurations
import org.springframework.boot.test.context.runner.ApplicationContextRunner
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
    fun tokenServiceIsRegistered() {
        ApplicationContextRunner().withConfiguration(AutoConfigurations.of(OAuth2ReactiveClientAutoConfiguration::class.java))
            .run {
                assertThat(it).getBean(JwtBearerTokenResolver::class.java).isNotNull()
                assertThat(it).getBean(OAuth2AccessTokenService::class.java).isNotNull()
            }
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
            assertThat(recordedRequest.headers["header1"]).isEqualTo("headervalue1")
            assertThat(recordedRequest.headers["header2"]).isEqualTo("headervalue2")
            assertThat(body).contains("param1=value1")
            assertThat(body).contains("param2=value2")
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
          }
          """
    }
}