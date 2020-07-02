package no.nav.security.token.support.client.core.oauth2;

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import no.nav.security.token.support.client.core.*;
import no.nav.security.token.support.client.core.http.SimpleOAuth2HttpClient;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import static no.nav.security.token.support.client.core.TestUtils.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class ExchangeTokenClientTest {

    private static final String TOKEN_RESPONSE = "{\n" +
        "    \"token_type\": \"Bearer\",\n" +
        "    \"scope\": \"scope1 scope2\",\n" +
        "    \"expires_at\": 1568141495,\n" +
        "    \"expires_in\": 3599,\n" +
        "    \"ext_expires_in\": 3599,\n" +
        "    \"access_token\": \"<base64URL>\"\n" +
        "}\n";

    private static final String ERROR_RESPONSE = "{\"error\": \"some client error occurred\"}";

    private String tokenEndpointUrl;
    private MockWebServer server;

    private ExchangeTokenClient exchangeTokenClient;

    private String subjectToken;

    @BeforeEach
    void setup() throws IOException {
        this.server = new MockWebServer();
        this.server.start();
        this.tokenEndpointUrl = this.server.url("/oauth2/v2/token").toString();
        this.exchangeTokenClient = new ExchangeTokenClient(new SimpleOAuth2HttpClient());
        this.subjectToken = jwt("somesub").serialize();
    }

    @AfterEach
    void cleanup() throws Exception {
        this.server.shutdown();
    }

    @Test
    void getTokenResponseWithPrivateKeyJwtAndExchangeProperties() throws InterruptedException {
        this.server.enqueue(jsonResponse(TOKEN_RESPONSE));
        ClientProperties clientProperties = tokenExchangeClientProperties(
            tokenEndpointUrl,
            OAuth2GrantType.TOKEN_EXCHANGE,
            "src/test/resources/jwk.json",
            subjectToken
        )
            .toBuilder()
            .authentication(ClientAuthenticationProperties.builder()
                .clientId("client")
                .clientAuthMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .clientJwk("src/test/resources/jwk.json")
                .build())
            .build();

        OAuth2AccessTokenResponse response =
            exchangeTokenClient.getTokenResponse(new ExchangeGrantRequest(clientProperties));
        RecordedRequest recordedRequest = this.server.takeRequest();
        assertPostMethodAndJsonHeaders(recordedRequest);
        String body = recordedRequest.getBody().readUtf8();
        assertThatClientAuthMethodIsPrivateKeyJwt(body, clientProperties);
        assertThatRequestBodyContainsTokenExchangeFormParameters(body);
        assertThatResponseContainsAccessToken(response);
    }

    @Test
    void getTokenResponseError() {
        this.server.enqueue(jsonResponse(ERROR_RESPONSE).setResponseCode(400));
        assertThatExceptionOfType(OAuth2ClientException.class)
            .isThrownBy(() -> exchangeTokenClient.getTokenResponse(new ExchangeGrantRequest(clientProperties(
                tokenEndpointUrl,
                OAuth2GrantType.TOKEN_EXCHANGE
            ))));
    }

    private static void assertThatResponseContainsAccessToken(OAuth2AccessTokenResponse response) {
        assertThat(response).isNotNull();
        assertThat(response.getAccessToken()).isNotBlank();
        assertThat(response.getExpiresAt()).isGreaterThan(0);
        assertThat(response.getExpiresIn()).isGreaterThan(0);
    }

    private static void assertThatClientAuthMethodIsPrivateKeyJwt(
        String body,
        ClientProperties clientProperties) {
        ClientAuthenticationProperties auth = clientProperties.getAuthentication();
        assertThat(auth.getClientAuthMethod().getValue()).isEqualTo("private_key_jwt");
        assertThat(body).contains("client_id=" + encodeValue(auth.getClientId()));
        assertThat(body).contains("client_assertion_type=" + encodeValue(
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"));
        assertThat(body).contains("client_assertion=" + "ey");
    }

    private void assertThatRequestBodyContainsTokenExchangeFormParameters(String formParameters) {
        assertThat(formParameters).contains(OAuth2ParameterNames.GRANT_TYPE + "=" + encodeValue(OAuth2GrantType.TOKEN_EXCHANGE.getValue()));
        assertThat(formParameters).contains(OAuth2ParameterNames.AUDIENCE + "=audience1");
        assertThat(formParameters).contains(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE + "=" + encodeValue("urn:ietf:params:oauth:token-type:jwt"));
        assertThat(formParameters).contains(OAuth2ParameterNames.SUBJECT_TOKEN + "=" + subjectToken);
    }
}
