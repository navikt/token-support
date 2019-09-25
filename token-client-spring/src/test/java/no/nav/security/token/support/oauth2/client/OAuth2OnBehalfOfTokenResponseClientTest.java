package no.nav.security.token.support.oauth2.client;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import no.nav.security.token.support.oauth2.OAuth2GrantType;
import no.nav.security.token.support.oauth2.OAuth2ParameterNames;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockitoAnnotations;
import org.springframework.web.client.RestTemplate;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;

class OAuth2OnBehalfOfTokenResponseClientTest {

    private static final String TOKEN_RESPONSE = "{\n" +
        "    \"token_type\": \"Bearer\",\n" +
        "    \"scope\": \"api://a1fd9dc1-2590-4e10-86a1-bc611c96dc17/defaultaccess api://a1fd9dc1-2590-4e10-86a1-bc611c96dc17/.default\",\n" +
        "    \"expires_at\": 1568141495,\n" +
        "    \"ext_expires_in\": 3599,\n" +
        "    \"access_token\": \"<base64URL>\",\n" +
        "    \"refresh_token\": \"<base64URL>\"\n" +
        "}\n";

    private static final String TOKEN_ENDPOINT = "/oauth2/v2.0/token";
    private OnBehalfOfTokenResponseClient onBehalfOfTokenResponseClient;
    private int port;
    private WireMockServer wireMockServer;

    @BeforeEach
    void setup() {
        MockitoAnnotations.initMocks(this);
        wireMockServer = new WireMockServer(wireMockConfig().dynamicPort());
        wireMockServer.start();
        port = wireMockServer.port();
        setupStub();
        onBehalfOfTokenResponseClient = new OnBehalfOfTokenResponseClient(new RestTemplate());
    }

    @AfterEach
    void teardown() {
        wireMockServer.stop();
    }

    private void setupStub() {
        wireMockServer.stubFor(post(urlEqualTo("/oauth2/v2.0/token"))
            .willReturn(aResponse().withHeader("Content-Type", "application/json")
                .withStatus(200)
                .withBody(TOKEN_RESPONSE)));
    }

    @Test
    void getTokenResponse() {
        List<String> scopes = Collections.singletonList("api://a1fd9dc1-2590-4e10-86a1-bc611c96dc17/.default");
        String assertion = createJwt();
        OnBehalfOfGrantRequest oAuth2OnBehalfOfGrantRequest = new OnBehalfOfGrantRequest(
            OAuth2ClientConfig.OAuth2ClientProperties.builder()
                .clientAuthMethod("client_secret_basic")
                .clientId("someClient")
                .clientSecret("someSecret")
                .grantType(OAuth2GrantType.JWT_BEARER)
                .scope(Arrays.asList("scope1", "scope2"))
                .tokenEndpointUrl("http://localhost:" + port + TOKEN_ENDPOINT)
                .build()
            , assertion);
        Map<String, String> response = onBehalfOfTokenResponseClient.getTokenResponse(oAuth2OnBehalfOfGrantRequest);
        assertThat(response).containsKeys(OAuth2ParameterNames.ACCESS_TOKEN);
        assertThat(response.get(OAuth2ParameterNames.ACCESS_TOKEN)).isNotBlank();
    }


    private static String createJwt() {
        Instant expiry = LocalDateTime.now().atZone(ZoneId.systemDefault()).plusSeconds(60).toInstant();
        JWT jwt = new PlainJWT(new JWTClaimsSet.Builder()
            .subject("someUser")
            .audience("thisapi")
            .expirationTime(Date.from(expiry))
            .build());
        return jwt.serialize();
    }
}
