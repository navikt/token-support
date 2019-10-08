package no.nav.security.token.support.oauth2.client;


import no.nav.security.token.support.oauth2.ClientConfigurationProperties;
import no.nav.security.token.support.oauth2.OAuth2GrantType;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URI;
import java.util.Arrays;

import static no.nav.security.token.support.oauth2.client.TestUtils.assertPostMethodAndJsonHeaders;
import static no.nav.security.token.support.oauth2.client.TestUtils.jsonResponse;
import static org.assertj.core.api.Assertions.assertThat;

class ClientCredentialsTokenClientTest {

    private static final String TOKEN_RESPONSE = "{\n" +
        "    \"token_type\": \"Bearer\",\n" +
        "    \"scope\": \"scope1 scope2\",\n" +
        "    \"expires_at\": 1568141495,\n" +
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
        this.client = new ClientCredentialsTokenClient(new RestTemplate());
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

    private ClientConfigurationProperties.ClientProperties oAuth2Client() {
        ClientConfigurationProperties.ClientProperties clientProperties = new ClientConfigurationProperties.ClientProperties();
        clientProperties.setClientAuthMethod("client_secret_basic");
        clientProperties.setClientId("myid");
        clientProperties.setClientSecret("mysecret");
        clientProperties.setScope(Arrays.asList("scope1", "scope2"));
        clientProperties.setGrantType(OAuth2GrantType.CLIENT_CREDENTIALS);
        clientProperties.setTokenEndpointUrl(URI.create(tokenEndpointUrl));
        return clientProperties;
    }

}
