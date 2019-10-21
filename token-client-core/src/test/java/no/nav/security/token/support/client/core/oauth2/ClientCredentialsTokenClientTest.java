package no.nav.security.token.support.client.core.oauth2;

import no.nav.security.token.support.client.core.ClientProperties;
import no.nav.security.token.support.client.core.OAuth2ClientException;
import no.nav.security.token.support.client.core.OAuth2GrantType;
import no.nav.security.token.support.client.core.http.SimpleOAuth2HttpClient;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class ClientCredentialsTokenClientTest {

    private static final String CONTENT_TYPE_FORM_URL_ENCODED = "application/x-www-form-urlencoded;charset=UTF-8";
    private static final String CONTENT_TYPE_JSON = "application/json;charset=UTF-8";

    private static final String TOKEN_RESPONSE = "{\n" +
        "    \"token_type\": \"Bearer\",\n" +
        "    \"scope\": \"scope1 scope2\",\n" +
        "    \"expires_at\": 1568141495,\n" +
        "    \"expires_in\": 3599,\n" +
        "    \"ext_expires_in\": 3599,\n" +
        "    \"access_token\": \"<base64URL>\",\n" +
        "    \"refresh_token\": \"<base64URL>\"\n" +
        "}\n";

    private static final String ERROR_RESPONSE = "{\"error\": \"some client error occurred\"}";

    private String tokenEndpointUrl;
    private MockWebServer server;

    private ClientCredentialsTokenClient client;

    @BeforeEach
    void setup() throws IOException {
        this.server = new MockWebServer();
        this.server.start();
        this.tokenEndpointUrl = this.server.url("/oauth2/v2/token").toString();
        this.client = new ClientCredentialsTokenClient(new SimpleOAuth2HttpClient());
    }

    @AfterEach
    void cleanup() throws Exception {
        this.server.shutdown();
    }


    @Test
    void getTokenResponseSuccess() throws InterruptedException {
        this.server.enqueue(jsonResponse(TOKEN_RESPONSE));
        OAuth2AccessTokenResponse response = client.getTokenResponse(new ClientCredentialsGrantRequest(oAuth2Client()));
        RecordedRequest recordedRequest = this.server.takeRequest();
        assertPostMethodAndJsonHeaders(recordedRequest);

        String formParameters = recordedRequest.getBody().readUtf8();

        assertThat(formParameters).contains("grant_type=client_credentials");
        assertThat(formParameters).contains("scope=scope1+scope2");

        assertThat(response).isNotNull();
        assertThat(response.getAccessToken()).isNotBlank();
        assertThat(response.getExpiresAt()).isGreaterThan(0);
        assertThat(response.getExpiresIn()).isGreaterThan(0);
    }

    @Test
    void getTokenResponseError() {
        this.server.enqueue(jsonResponse(ERROR_RESPONSE).setResponseCode(400));

        assertThatExceptionOfType(OAuth2ClientException.class)
            .isThrownBy(() -> client.getTokenResponse(new ClientCredentialsGrantRequest(oAuth2Client())));
    }

    private ClientProperties oAuth2Client() {
        ClientProperties clientProperties = new ClientProperties();
        clientProperties.setClientAuthMethod("client_secret_basic");
        clientProperties.setClientId("myid");
        clientProperties.setClientSecret("mysecret");
        clientProperties.setScope(Arrays.asList("scope1", "scope2"));
        clientProperties.setGrantType(OAuth2GrantType.CLIENT_CREDENTIALS);
        clientProperties.setTokenEndpointUrl(URI.create(tokenEndpointUrl));
        return clientProperties;
    }

    private static MockResponse jsonResponse(String json) {
        return new MockResponse()
            .setHeader("Content-Type", "application/json;charset=UTF-8")
            .setBody(json);
    }

    private static void assertPostMethodAndJsonHeaders(RecordedRequest recordedRequest) {
        assertThat(recordedRequest.getMethod()).isEqualTo("POST");
        assertThat(recordedRequest.getHeader("Accept")).isEqualTo(CONTENT_TYPE_JSON);
        assertThat(recordedRequest.getHeader("Content-Type")).isEqualTo(CONTENT_TYPE_FORM_URL_ENCODED);
    }
}
