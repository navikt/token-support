package no.nav.security.token.support.oauth2.client;

import no.nav.security.token.support.oauth2.ClientConfigurationProperties;
import no.nav.security.token.support.oauth2.OAuth2ClientException;
import no.nav.security.token.support.oauth2.OAuth2GrantType;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockitoAnnotations;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.util.Arrays;

import static no.nav.security.token.support.oauth2.client.TestUtils.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class OnBehalfOfTokenResponseClientTest {

    private static final String TOKEN_RESPONSE = "{\n" +
        "    \"token_type\": \"Bearer\",\n" +
        "    \"scope\": \"scope1 scope2\",\n" +
        "    \"expires_at\": 1568141495,\n" +
        "    \"ext_expires_in\": 3599,\n" +
        "    \"access_token\": \"<base64URL>\",\n" +
        "    \"refresh_token\": \"<base64URL>\"\n" +
        "}\n";

    private static final String ERROR_RESPONSE = "{\"error\": \"some client error occurred\"}";

    private static final String TOKEN_ENDPOINT = "/oauth2/v2.0/token";
    private OnBehalfOfTokenResponseClient onBehalfOfTokenResponseClient;
    private String tokenEndpointUrl;
    private MockWebServer server;

    @BeforeEach
    void setup() throws IOException {
        MockitoAnnotations.initMocks(this);
        this.server = new MockWebServer();
        this.server.start();
        this.tokenEndpointUrl = this.server.url(TOKEN_ENDPOINT).toString();
        onBehalfOfTokenResponseClient = new OnBehalfOfTokenResponseClient(new RestTemplate());
    }

    @AfterEach
    void teardown() throws IOException {
        server.shutdown();
    }


    @Test
    void getTokenResponse() throws InterruptedException, UnsupportedEncodingException {
        this.server.enqueue(jsonResponse(TOKEN_RESPONSE));
        String assertion = createJwt();
        OnBehalfOfGrantRequest oAuth2OnBehalfOfGrantRequest = new OnBehalfOfGrantRequest(oAuth2Client(), assertion);
        OAuth2AccessTokenResponse response = onBehalfOfTokenResponseClient.getTokenResponse(oAuth2OnBehalfOfGrantRequest);

        RecordedRequest recordedRequest = server.takeRequest();
        assertPostMethodAndJsonHeaders(recordedRequest);
        String formParameters = recordedRequest.getBody().readUtf8();
        assertThat(formParameters).contains("grant_type=" + URLEncoder.encode(OAuth2GrantType.JWT_BEARER.getValue(), "UTF-8"));
        assertThat(formParameters).contains("scope=scope1+scope2");
        assertThat(formParameters).contains("requested_token_use=on_behalf_of");
        assertThat(formParameters).contains("assertion=" + assertion);

        assertThat(response).isNotNull();
        assertThat(response.getAccessToken()).isNotBlank();
        assertThat(response.getExpiresAt()).isGreaterThan(0);
        assertThat(response.getExpiresIn()).isGreaterThan(0);
    }

    @Test
    void getTokenResponseWithError() {
        this.server.enqueue(jsonResponse(ERROR_RESPONSE).setResponseCode(400));
        String assertion = createJwt();
        ClientConfigurationProperties.ClientProperties clientProperties = oAuth2Client();
        OnBehalfOfGrantRequest oAuth2OnBehalfOfGrantRequest = new OnBehalfOfGrantRequest(clientProperties, assertion);
        assertThatExceptionOfType(OAuth2ClientException.class)
            .isThrownBy(() -> onBehalfOfTokenResponseClient.getTokenResponse(oAuth2OnBehalfOfGrantRequest))
            .withMessageContaining(ERROR_RESPONSE);
    }

    private ClientConfigurationProperties.ClientProperties oAuth2Client() {
        ClientConfigurationProperties.ClientProperties clientProperties = new ClientConfigurationProperties.ClientProperties();
        clientProperties.setClientAuthMethod("client_secret_basic");
        clientProperties.setClientId("myid");
        clientProperties.setClientSecret("mysecret");
        clientProperties.setScope(Arrays.asList("scope1", "scope2"));
        clientProperties.setGrantType(OAuth2GrantType.JWT_BEARER);
        clientProperties.setTokenEndpointUrl(URI.create(tokenEndpointUrl));
        return clientProperties;
    }
}
