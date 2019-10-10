package no.nav.security.token.support.oauth2.client;

import com.github.benmanes.caffeine.cache.Cache;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import no.nav.security.token.support.core.context.TokenValidationContext;
import no.nav.security.token.support.core.context.TokenValidationContextHolder;
import no.nav.security.token.support.core.jwt.JwtToken;
import no.nav.security.token.support.oauth2.ClientConfigurationProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static no.nav.security.token.support.oauth2.client.TestUtils.accessTokenResponse;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@SpringBootTest(classes = {ClientConfigurationProperties.class})
@ActiveProfiles("test")
class OAuth2AccessTokenServiceCacheTest {

    @Mock
    private OnBehalfOfTokenClient onBehalfOfTokenResponseClient;
    @Mock
    private ClientCredentialsTokenClient clientCredentialsTokenResponseClient;

    @Autowired
    private ClientConfigurationProperties clients;

    private TokenValidationContextHolder tokenValidationContextHolder;
    private Cache<OnBehalfOfGrantRequest, OAuth2AccessTokenResponse> oboCache;
    private Cache<ClientCredentialsGrantRequest, OAuth2AccessTokenResponse> clientCredentialsCache;
    private OAuth2AccessTokenService oAuth2AccessTokenService;

    @BeforeEach
    void setup() {
        MockitoAnnotations.initMocks(this);
        tokenValidationContextHolder = new TokenValidationContextHolder() {
            private TokenValidationContext ctx;

            @Override
            public TokenValidationContext getTokenValidationContext() {
                return ctx;
            }

            @Override
            public void setTokenValidationContext(TokenValidationContext tokenValidationContext) {
                this.ctx = tokenValidationContext;
            }
        };

        OAuth2ClientConfiguration oAuth2ClientConfiguration = new OAuth2ClientConfiguration();
        oboCache = oAuth2ClientConfiguration.cache(10, 1);
        clientCredentialsCache = oAuth2ClientConfiguration.cache(10, 1);

        oAuth2AccessTokenService = new OAuth2AccessTokenService(
            tokenValidationContextHolder,
            onBehalfOfTokenResponseClient,
            clientCredentialsTokenResponseClient);
        oAuth2AccessTokenService.setOnBehalfOfGrantCache(oboCache);
        oAuth2AccessTokenService.setClientCredentialsGrantCache(clientCredentialsCache);
    }

    @Test
    void getAccessTokenOnBehalfOf_WithCache_MultipleTimes_SameClientConfig() {
        ClientConfigurationProperties.ClientProperties clientProperties = clients.getRegistration().get("example1" +
            "-onbehalfof");

        tokenValidationContextHolder.setTokenValidationContext(tokenValidationContext("sub1"));

        //should invoke client and populate cache
        String firstAccessToken = "first_access_token";
        when(onBehalfOfTokenResponseClient.getTokenResponse(any(OnBehalfOfGrantRequest.class)))
            .thenReturn(accessTokenResponse(firstAccessToken, 60));

        OAuth2AccessTokenResponse oAuth2AccessTokenResponse1 =
            oAuth2AccessTokenService.getAccessToken(clientProperties);
        verify(onBehalfOfTokenResponseClient, times(1)).getTokenResponse(any(OnBehalfOfGrantRequest.class));
        assertThat(oAuth2AccessTokenResponse1).hasNoNullFieldsOrProperties();
        assertThat(oAuth2AccessTokenResponse1.getAccessToken()).isEqualTo("first_access_token");

        //should get response from cache and NOT invoke client
        reset(onBehalfOfTokenResponseClient);
        OAuth2AccessTokenResponse oAuth2AccessTokenResponse2 =
            oAuth2AccessTokenService.getAccessToken(clientProperties);
        verify(onBehalfOfTokenResponseClient, never()).getTokenResponse(any(OnBehalfOfGrantRequest.class));
        assertThat(oAuth2AccessTokenResponse2.getAccessToken()).isEqualTo("first_access_token");

        //another user/token but same clientconfig, should invoke client and populate cache
        tokenValidationContextHolder.setTokenValidationContext(tokenValidationContext("sub2"));

        reset(onBehalfOfTokenResponseClient);
        String secondAccessToken = "second_access_token";
        when(onBehalfOfTokenResponseClient.getTokenResponse(any(OnBehalfOfGrantRequest.class)))
            .thenReturn(accessTokenResponse(secondAccessToken, 60));
        OAuth2AccessTokenResponse oAuth2AccessTokenResponse3 =
            oAuth2AccessTokenService.getAccessToken(clientProperties);
        verify(onBehalfOfTokenResponseClient, times(1)).getTokenResponse(any(OnBehalfOfGrantRequest.class));
        assertThat(oAuth2AccessTokenResponse3.getAccessToken()).isEqualTo(secondAccessToken);

    }

    @Test
    void getAccessTokenClientCredentials_WithCache_MultipleTimes() {
        ClientConfigurationProperties.ClientProperties clientProperties = clients.getRegistration().get("example1" +
            "-clientcredentials1");

        //should invoke client and populate cache
        String firstAccessToken = "first_access_token";
        when(clientCredentialsTokenResponseClient.getTokenResponse(any(ClientCredentialsGrantRequest.class)))
            .thenReturn(accessTokenResponse(firstAccessToken, 60));

        OAuth2AccessTokenResponse oAuth2AccessTokenResponse1 =
            oAuth2AccessTokenService.getAccessToken(clientProperties);
        verify(clientCredentialsTokenResponseClient, times(1)).getTokenResponse(any(ClientCredentialsGrantRequest.class));
        assertThat(oAuth2AccessTokenResponse1).hasNoNullFieldsOrProperties();
        assertThat(oAuth2AccessTokenResponse1.getAccessToken()).isEqualTo("first_access_token");

        //should get response from cache and NOT invoke client
        reset(clientCredentialsTokenResponseClient);
        OAuth2AccessTokenResponse oAuth2AccessTokenResponse2 =
            oAuth2AccessTokenService.getAccessToken(clientProperties);
        verify(clientCredentialsTokenResponseClient, never()).getTokenResponse(any(ClientCredentialsGrantRequest.class));
        assertThat(oAuth2AccessTokenResponse2.getAccessToken()).isEqualTo("first_access_token");

        //another clientconfig, should invoke client and populate cache

        clientProperties = clients.getRegistration().get("example1-clientcredentials2");

        reset(clientCredentialsTokenResponseClient);
        String secondAccessToken = "second_access_token";
        when(clientCredentialsTokenResponseClient.getTokenResponse(any(ClientCredentialsGrantRequest.class)))
            .thenReturn(accessTokenResponse(secondAccessToken, 60));
        OAuth2AccessTokenResponse oAuth2AccessTokenResponse3 =
            oAuth2AccessTokenService.getAccessToken(clientProperties);
        verify(clientCredentialsTokenResponseClient, times(1)).getTokenResponse(any(ClientCredentialsGrantRequest.class));
        assertThat(oAuth2AccessTokenResponse3.getAccessToken()).isEqualTo(secondAccessToken);

    }

    @Test
    void testCacheEntryIsEvictedOnExpiry() throws InterruptedException {
        ClientConfigurationProperties.ClientProperties clientProperties = clients.getRegistration().get("example1" +
            "-onbehalfof");
        tokenValidationContextHolder.setTokenValidationContext(tokenValidationContext("sub1"));

        //should invoke client and populate cache
        String firstAccessToken = "first_access_token";
        when(onBehalfOfTokenResponseClient.getTokenResponse(any(OnBehalfOfGrantRequest.class)))
            .thenReturn(accessTokenResponse(firstAccessToken, 1));

        OAuth2AccessTokenResponse oAuth2AccessTokenResponse1 =
            oAuth2AccessTokenService.getAccessToken(clientProperties);
        verify(onBehalfOfTokenResponseClient, times(1)).getTokenResponse(any(OnBehalfOfGrantRequest.class));
        assertThat(oAuth2AccessTokenResponse1).hasNoNullFieldsOrProperties();
        assertThat(oAuth2AccessTokenResponse1.getAccessToken()).isEqualTo("first_access_token");

        Thread.sleep(1000);

        //entry should be missing from cache due to expiry
        reset(onBehalfOfTokenResponseClient);
        String secondAccessToken = "second_access_token";
        when(onBehalfOfTokenResponseClient.getTokenResponse(any(OnBehalfOfGrantRequest.class)))
            .thenReturn(accessTokenResponse(secondAccessToken, 1));
        OAuth2AccessTokenResponse oAuth2AccessTokenResponse2 =
            oAuth2AccessTokenService.getAccessToken(clientProperties);
        verify(onBehalfOfTokenResponseClient, times(1)).getTokenResponse(any(OnBehalfOfGrantRequest.class));
        assertThat(oAuth2AccessTokenResponse2.getAccessToken()).isEqualTo(secondAccessToken);
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
