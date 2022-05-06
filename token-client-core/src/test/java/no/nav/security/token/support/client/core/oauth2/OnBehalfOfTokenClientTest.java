package no.nav.security.token.support.client.core.oauth2;

import no.nav.security.token.support.client.core.ClientProperties;
import no.nav.security.token.support.client.core.OAuth2ClientException;
import no.nav.security.token.support.client.core.OAuth2GrantType;
import no.nav.security.token.support.client.core.http.SimpleOAuth2HttpClient;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockitoAnnotations;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import static no.nav.security.token.support.client.core.TestUtils.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class OnBehalfOfTokenClientTest {

    private static final String TOKEN_RESPONSE = "{\n" +
        "    \"token_type\": \"Bearer\",\n" +
        "    \"scope\": \"scope1 scope2\",\n" +
        "    \"expires_at\": 1568141495,\n" +
        "    \"ext_expires_in\": 3599,\n" +
        "    \"expires_in\": 3599,\n" +
        "    \"access_token\": \"<base64URL>\",\n" +
        "    \"refresh_token\": \"<base64URL>\"\n" +
        "}\n";

    private static final String ERROR_RESPONSE = "{\"error\": \"some client error occurred\"}";

    private static final String TOKEN_ENDPOINT = "/oauth2/v2.0/token";
    private OnBehalfOfTokenClient onBehalfOfTokenResponseClient;
    private String tokenEndpointUrl;
    private MockWebServer server;

    @BeforeEach
    void setup() throws IOException {
        MockitoAnnotations.initMocks(this);
        this.server = new MockWebServer();
        this.server.start();
        this.tokenEndpointUrl = this.server.url(TOKEN_ENDPOINT).toString();
        onBehalfOfTokenResponseClient = new OnBehalfOfTokenClient(new SimpleOAuth2HttpClient());
    }

    @AfterEach
    void teardown() throws IOException {
        server.shutdown();
    }

    @Test
    void getTokenResponse() throws InterruptedException {
        this.server.enqueue(jsonResponse(TOKEN_RESPONSE));
        String assertion = jwt("sub1").serialize();
        ClientProperties clientProperties = clientProperties(this.tokenEndpointUrl, OAuth2GrantType.JWT_BEARER);
        OnBehalfOfGrantRequest oAuth2OnBehalfOfGrantRequest = new OnBehalfOfGrantRequest(clientProperties, assertion);
        OAuth2AccessTokenResponse response =
            onBehalfOfTokenResponseClient.getTokenResponse(oAuth2OnBehalfOfGrantRequest);

        RecordedRequest recordedRequest = server.takeRequest();
        assertPostMethodAndJsonHeaders(recordedRequest);
        String formParameters = recordedRequest.getBody().readUtf8();
        assertThat(formParameters).contains("grant_type=" + URLEncoder.encode(OAuth2GrantType.JWT_BEARER.value(),
            StandardCharsets.UTF_8));
        assertThat(formParameters).contains("scope=scope1+scope2");
        assertThat(formParameters).contains("requested_token_use=on_behalf_of");
        assertThat(formParameters).contains("assertion=" + assertion);

        assertThat(response).isNotNull();
        assertThat(response.getAccessToken()).isNotBlank();
        assertThat(response.getExpiresAt()).isPositive();
        assertThat(response.getExpiresIn()).isPositive();
    }

    @Test
    void getTokenResponseWithError() {
        this.server.enqueue(jsonResponse(ERROR_RESPONSE).setResponseCode(400));
        String assertion = jwt("sub1").serialize();
        ClientProperties clientProperties = clientProperties(this.tokenEndpointUrl, OAuth2GrantType.JWT_BEARER);
        OnBehalfOfGrantRequest oAuth2OnBehalfOfGrantRequest = new OnBehalfOfGrantRequest(clientProperties, assertion);
        assertThatExceptionOfType(OAuth2ClientException.class)
            .isThrownBy(() -> onBehalfOfTokenResponseClient.getTokenResponse(oAuth2OnBehalfOfGrantRequest))
            .withMessageContaining(ERROR_RESPONSE);
    }
}
