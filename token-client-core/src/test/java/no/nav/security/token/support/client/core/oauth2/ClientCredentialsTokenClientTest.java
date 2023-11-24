package no.nav.security.token.support.client.core.oauth2;

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import no.nav.security.token.support.client.core.ClientAuthenticationProperties;
import no.nav.security.token.support.client.core.ClientProperties;
import no.nav.security.token.support.client.core.OAuth2ClientException;
import no.nav.security.token.support.client.core.OAuth2GrantType;
import no.nav.security.token.support.client.core.http.SimpleOAuth2HttpClient;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.util.List;

import static com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_POST;
import static com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.PRIVATE_KEY_JWT;
import static no.nav.security.token.support.client.core.OAuth2GrantType.CLIENT_CREDENTIALS;
import static no.nav.security.token.support.client.core.TestUtils.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class ClientCredentialsTokenClientTest {

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
    void getTokenResponseWithDefaultClientAuthMethod() throws InterruptedException {
        this.server.enqueue(jsonResponse(TOKEN_RESPONSE));
        ClientProperties clientProperties = clientProperties(tokenEndpointUrl, CLIENT_CREDENTIALS);
        OAuth2AccessTokenResponse response =
            client.getTokenResponse(new ClientCredentialsGrantRequest(clientProperties));
        RecordedRequest recordedRequest = this.server.takeRequest();
        assertPostMethodAndJsonHeaders(recordedRequest);
        assertThatClientAuthMethodIsClientSecretBasic(recordedRequest, clientProperties);
        String body = recordedRequest.getBody().readUtf8();
        assertThatRequestBodyContainsFormParameters(body);
        assertThatResponseContainsAccessToken(response);

    }

    @Test
    void getTokenResponseWithClientSecretBasic() throws InterruptedException {
        this.server.enqueue(jsonResponse(TOKEN_RESPONSE));
        ClientProperties clientProperties = clientProperties(tokenEndpointUrl, CLIENT_CREDENTIALS);
        OAuth2AccessTokenResponse response =
            client.getTokenResponse(new ClientCredentialsGrantRequest(clientProperties));
        RecordedRequest recordedRequest = this.server.takeRequest();
        assertPostMethodAndJsonHeaders(recordedRequest);
        assertThatClientAuthMethodIsClientSecretBasic(recordedRequest, clientProperties);
        String body = recordedRequest.getBody().readUtf8();
        assertThatRequestBodyContainsFormParameters(body);
        assertThatResponseContainsAccessToken(response);

    }

    @Test
    void getTokenResponseWithClientSecretPost() throws InterruptedException {
        this.server.enqueue(jsonResponse(TOKEN_RESPONSE));
      /*  ClientProperties clientProperties = clientProperties(tokenEndpointUrl, CLIENT_CREDENTIALS)
            .toBuilder()
            .authentication(ClientAuthenticationProperties.builder("client",CLIENT_SECRET_POST)
                .clientSecret("secret")
                .build())
            .build();*/
        var clientProperties  = ClientProperties.builder(CLIENT_CREDENTIALS,ClientAuthenticationProperties.builder("client",CLIENT_SECRET_POST).clientSecret("secret").build())
                .tokenEndpointUrl(URI.create(tokenEndpointUrl))
                .scope(List.of("scope1", "scope2"))
                .build();

        OAuth2AccessTokenResponse response =
            client.getTokenResponse(new ClientCredentialsGrantRequest(clientProperties));
        RecordedRequest recordedRequest = this.server.takeRequest();
        assertPostMethodAndJsonHeaders(recordedRequest);
        String body = recordedRequest.getBody().readUtf8();
        assertThatClientAuthMethodIsClientSecretPost(body, clientProperties);
        assertThatRequestBodyContainsFormParameters(body);
        assertThatResponseContainsAccessToken(response);

    }

    @Test
    void getTokenResponseWithPrivateKeyJwt() throws InterruptedException {
        this.server.enqueue(jsonResponse(TOKEN_RESPONSE));
    /*    ClientProperties clientProperties = clientProperties(tokenEndpointUrl, CLIENT_CREDENTIALS)
            .toBuilder()
            .authentication(ClientAuthenticationProperties.builder("client",PRIVATE_KEY_JWT)
                .clientJwk("src/test/resources/jwk.json")
                .build())
            .build();
*/
        var clientProperties  = ClientProperties.builder(CLIENT_CREDENTIALS,ClientAuthenticationProperties.builder("client",PRIVATE_KEY_JWT)
                        .clientSecret("secret")
                        .clientJwk("src/test/resources/jwk.json")
                        .build())
                .tokenEndpointUrl(URI.create(tokenEndpointUrl))
                .scope(List.of("scope1", "scope2"))
                .build();

        OAuth2AccessTokenResponse response =
            client.getTokenResponse(new ClientCredentialsGrantRequest(clientProperties));
        RecordedRequest recordedRequest = this.server.takeRequest();
        assertPostMethodAndJsonHeaders(recordedRequest);
        String body = recordedRequest.getBody().readUtf8();
        assertThatClientAuthMethodIsPrivateKeyJwt(body, clientProperties);
        assertThatRequestBodyContainsFormParameters(body);
        assertThatResponseContainsAccessToken(response);
    }

    @Test
    void getTokenResponseError() {
        this.server.enqueue(jsonResponse(ERROR_RESPONSE).setResponseCode(400));
        assertThatExceptionOfType(OAuth2ClientException.class)
            .isThrownBy(() -> client.getTokenResponse(new ClientCredentialsGrantRequest(clientProperties(
                tokenEndpointUrl,
                CLIENT_CREDENTIALS
            ))));
    }

    private static void assertThatResponseContainsAccessToken(OAuth2AccessTokenResponse response) {
        assertThat(response).isNotNull();
        assertThat(response.getAccessToken()).isNotBlank();
        assertThat(response.getExpiresAt()).isPositive();
        assertThat(response.getExpiresIn()).isPositive();
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

    private static void assertThatClientAuthMethodIsClientSecretPost(
        String body,
        ClientProperties clientProperties) {
        ClientAuthenticationProperties auth = clientProperties.getAuthentication();
        assertThat(auth.getClientAuthMethod().getValue()).isEqualTo("client_secret_post");
        assertThat(body).contains("client_id=" + encodeValue(auth.getClientId()));
        assertThat(body).contains("client_secret=" + encodeValue(auth.getClientSecret()));
    }

    private static void assertThatClientAuthMethodIsClientSecretBasic(RecordedRequest recordedRequest,
                                                                      ClientProperties clientProperties) {
        ClientAuthenticationProperties auth = clientProperties.getAuthentication();
        assertThat(auth.getClientAuthMethod().getValue()).isEqualTo("client_secret_basic");
        assertThat(recordedRequest.getHeaders().get("Authorization")).isNotBlank();
        String usernamePwd = decodeBasicAuth(recordedRequest);
        assertThat(usernamePwd).isEqualTo(auth.getClientId() + ":" + auth.getClientSecret());
    }

    private static void assertThatRequestBodyContainsFormParameters(String formParameters) {
        assertThat(formParameters).contains("grant_type=client_credentials");
        assertThat(formParameters).contains("scope=scope1+scope2");
    }
}