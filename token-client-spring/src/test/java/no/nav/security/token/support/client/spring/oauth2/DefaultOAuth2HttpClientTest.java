package no.nav.security.token.support.client.spring.oauth2;

import no.nav.security.token.support.client.core.http.OAuth2HttpHeaders;
import no.nav.security.token.support.client.core.http.OAuth2HttpRequest;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockitoAnnotations;
import org.springframework.boot.web.client.RestTemplateBuilder;

import java.io.IOException;
import java.net.URI;

import static no.nav.security.token.support.client.spring.oauth2.TestUtils.jsonResponse;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

class DefaultOAuth2HttpClientTest {

    private static final String TOKEN_RESPONSE = "{\n" +
        "    \"token_type\": \"Bearer\",\n" +
        "    \"scope\": \"scope1 scope2\",\n" +
        "    \"expires_at\": 1568141495,\n" +
        "    \"ext_expires_in\": 3599,\n" +
        "    \"expires_in\": 3599,\n" +
        "    \"access_token\": \"<base64URL>\",\n" +
        "    \"refresh_token\": \"<base64URL>\"\n" +
        "}\n";

    private MockWebServer server;
    private URI tokenEndpointUrl;
    private DefaultOAuth2HttpClient client;

    @BeforeEach
    void setup() throws IOException {
        MockitoAnnotations.initMocks(this);
        server = new MockWebServer();
        server.start();
        this.tokenEndpointUrl = server.url("/oauth2/token").uri();
        this.client = new DefaultOAuth2HttpClient(new RestTemplateBuilder());
    }

    @AfterEach
    void teardown() throws IOException {
        server.shutdown();
    }

    @Test
    void testPostAllHeadersAndFormParametersShouldBePresent() throws InterruptedException {
        server.enqueue(jsonResponse(TOKEN_RESPONSE));
        OAuth2HttpRequest request = OAuth2HttpRequest.builder()
            .tokenEndpointUrl(tokenEndpointUrl)
            .formParameter("param1", "value1")
            .formParameter("param2", "value2")
            .oAuth2HttpHeaders(OAuth2HttpHeaders.builder()
                .header("header1", "headervalue1")
                .header("header2", "headervalue2")
                .build())
            .build();
        client.post(request);
        RecordedRequest recordedRequest = server.takeRequest();
        var body = recordedRequest.getBody().readUtf8();
        assertThat(recordedRequest.getHeaders().get("header1")).isEqualTo("headervalue1");
        assertThat(recordedRequest.getHeaders().get("header2")).isEqualTo("headervalue2");
        assertThat(body).contains("param1=value1");
        assertThat(body).contains("param2=value2");
    }
}
