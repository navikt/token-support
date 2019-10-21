package no.nav.security.token.support.client.spring.oauth2;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import lombok.extern.slf4j.Slf4j;
import no.nav.security.token.support.client.core.ClientProperties;
import no.nav.security.token.support.client.core.OAuth2GrantType;
import no.nav.security.token.support.client.core.context.OnBehalfOfAssertionResolver;
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenResponse;
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenService;
import no.nav.security.token.support.client.spring.ClientConfigurationProperties;
import no.nav.security.token.support.core.context.TokenValidationContext;
import no.nav.security.token.support.core.context.TokenValidationContextHolder;
import no.nav.security.token.support.core.jwt.JwtToken;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;

import static no.nav.security.token.support.client.spring.oauth2.TestUtils.jsonResponse;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@Slf4j
@SpringBootTest(classes = {ConfigurationWithCacheEnabled.class})
@ActiveProfiles("test")
class OAuth2AccessTokenServiceIntegrationTest {

    private static final String TOKEN_RESPONSE = "{\n" +
        "    \"token_type\": \"Bearer\",\n" +
        "    \"scope\": \"scope1 scope2\",\n" +
        "    \"expires_at\": 1568141495,\n" +
        "    \"ext_expires_in\": 3599,\n" +
        "    \"expires_in\": 3599,\n" +
        "    \"access_token\": \"<base64URL>\",\n" +
        "    \"refresh_token\": \"<base64URL>\"\n" +
        "}\n";

    @MockBean
    private TokenValidationContextHolder tokenValidationContextHolder;
    @Autowired
    private OAuth2AccessTokenService oAuth2AccessTokenService;
    @Autowired
    private ClientConfigurationProperties clientConfigurationProperties;
    @Autowired
    private OnBehalfOfAssertionResolver assertionResolver;

    private MockWebServer server;
    private URI tokenEndpointUrl;

    @BeforeEach
    void setup() throws IOException {
        MockitoAnnotations.initMocks(this);
        server = new MockWebServer();
        server.start();
        this.tokenEndpointUrl = server.url("/oauth2/token").uri();
    }

    @AfterEach
    void teardown() throws IOException {
        server.shutdown();
    }

    @Test
    void getAccessTokenOnBehalfOf() throws InterruptedException {
        ClientProperties clientProperties = clientConfigurationProperties.getRegistration().get("example1-onbehalfof");
        assertThat(clientProperties).isNotNull();
        clientProperties.setTokenEndpointUrl(tokenEndpointUrl);
        server.enqueue(jsonResponse(TOKEN_RESPONSE));

        when(tokenValidationContextHolder.getTokenValidationContext()).thenReturn(tokenValidationContext("sub1"));
        OAuth2AccessTokenResponse response = oAuth2AccessTokenService.getAccessToken(clientProperties);
        var request = server.takeRequest();
        var headers = request.getHeaders();
        var body = request.getBody().readUtf8();
        assertThat(headers.get("Content-Type")).contains("application/x-www-form-urlencoded");
        assertThat(headers.get("Authorization")).isNotBlank();

        var usernamePwd = Optional.ofNullable(headers.get("Authorization"))
            .map(s -> s.split("Basic "))
            .filter(pair -> pair.length == 2)
            .map(pair -> Base64.getDecoder().decode(pair[1]))
            .map(bytes -> new String(bytes, StandardCharsets.UTF_8))
            .orElse("");

        assertThat(usernamePwd).isEqualTo(clientProperties.getClientId() + ":" + clientProperties.getClientSecret());
        assertThat(body).contains("grant_type=" + URLEncoder.encode(OAuth2GrantType.JWT_BEARER.getValue(),
            StandardCharsets.UTF_8));
        assertThat(body).contains("scope=" + URLEncoder.encode(String.join(" ", clientProperties.getScope()),
            StandardCharsets.UTF_8));
        assertThat(body).contains("requested_token_use=on_behalf_of");
        assertThat(body).contains("assertion=" + assertionResolver.assertion().orElse(null));

        assertThat(response).isNotNull();
        assertThat(response.getAccessToken()).isNotBlank();
        assertThat(response.getExpiresAt()).isGreaterThan(0);
        assertThat(response.getExpiresIn()).isGreaterThan(0);
    }

    @Test
    void getAccessTokenClientCredentials() throws InterruptedException {
        ClientProperties clientProperties = clientConfigurationProperties.getRegistration()
            .get("example1-clientcredentials1");

        assertThat(clientProperties).isNotNull();
        clientProperties.setTokenEndpointUrl(tokenEndpointUrl);
        server.enqueue(jsonResponse(TOKEN_RESPONSE));

        OAuth2AccessTokenResponse response = oAuth2AccessTokenService.getAccessToken(clientProperties);
        var request = server.takeRequest();
        var headers = request.getHeaders();
        var body = request.getBody().readUtf8();
        assertThat(headers.get("Content-Type")).contains("application/x-www-form-urlencoded");
        assertThat(headers.get("Authorization")).isNotBlank();

        var usernamePwd = Optional.ofNullable(headers.get("Authorization"))
            .map(s -> s.split("Basic "))
            .filter(pair -> pair.length == 2)
            .map(pair -> Base64.getDecoder().decode(pair[1]))
            .map(bytes -> new String(bytes, StandardCharsets.UTF_8))
            .orElse("");

        assertThat(usernamePwd).isEqualTo(clientProperties.getClientId() + ":" + clientProperties.getClientSecret());
        assertThat(body).contains("grant_type=client_credentials");
        assertThat(body).contains("scope=" + URLEncoder.encode(String.join(" ", clientProperties.getScope()),
            StandardCharsets.UTF_8));
        assertThat(body).doesNotContain("requested_token_use=on_behalf_of");
        assertThat(body).doesNotContain("assertion=");

        assertThat(response).isNotNull();
        assertThat(response.getAccessToken()).isNotBlank();
        assertThat(response.getExpiresAt()).isGreaterThan(0);
        assertThat(response.getExpiresIn()).isGreaterThan(0);
    }


    private static TokenValidationContext tokenValidationContext(String sub) {
        Instant expiry = LocalDateTime.now().atZone(ZoneId.systemDefault()).plusSeconds(60).toInstant();
        JWT jwt = new PlainJWT(new JWTClaimsSet.Builder()
            .subject(sub)
            .audience("thisapi")
            .issuer("someIssuer")
            .expirationTime(Date.from(expiry))
            .claim("jti", UUID.randomUUID().toString())
            .build());

        Map<String, JwtToken> map = new HashMap<>();
        map.put("issuer1", new JwtToken(jwt.serialize()));
        return new TokenValidationContext(map);
    }
}
