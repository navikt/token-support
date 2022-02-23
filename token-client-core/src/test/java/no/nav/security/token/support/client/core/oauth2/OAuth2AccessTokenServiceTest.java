package no.nav.security.token.support.client.core.oauth2;

import com.github.benmanes.caffeine.cache.Cache;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import no.nav.security.token.support.client.core.ClientProperties;
import no.nav.security.token.support.client.core.OAuth2CacheFactory;
import no.nav.security.token.support.client.core.OAuth2ClientException;
import no.nav.security.token.support.client.core.OAuth2GrantType;
import no.nav.security.token.support.client.core.context.JwtBearerTokenResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

import static no.nav.security.token.support.client.core.TestUtils.clientProperties;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.*;


class OAuth2AccessTokenServiceTest {

    @Mock
    private OnBehalfOfTokenClient onBehalfOfTokenResponseClient;
    @Mock
    private ClientCredentialsTokenClient clientCredentialsTokenResponseClient;
    @Mock
    private TokenExchangeClient exchangeTokeResponseClient;

    @Mock
    private JwtBearerTokenResolver assertionResolver;

    private OAuth2AccessTokenService oAuth2AccessTokenService;

    @BeforeEach
    void setup() {
        MockitoAnnotations.initMocks(this);

        Cache<OnBehalfOfGrantRequest, OAuth2AccessTokenResponse> oboCache =
            OAuth2CacheFactory.accessTokenResponseCache(10, 1);
        Cache<ClientCredentialsGrantRequest, OAuth2AccessTokenResponse> clientCredentialsCache =
            OAuth2CacheFactory.accessTokenResponseCache(10, 1);
        Cache<TokenExchangeGrantRequest, OAuth2AccessTokenResponse> exchangeTokenCache =
            OAuth2CacheFactory.accessTokenResponseCache(10, 1);

        oAuth2AccessTokenService = new OAuth2AccessTokenService(
            assertionResolver,
            onBehalfOfTokenResponseClient,
            clientCredentialsTokenResponseClient,
            exchangeTokeResponseClient);
        oAuth2AccessTokenService.setOnBehalfOfGrantCache(oboCache);
        oAuth2AccessTokenService.setClientCredentialsGrantCache(clientCredentialsCache);
        oAuth2AccessTokenService.setExchangeGrantCache(exchangeTokenCache);
    }

    @Test
    void getAccessTokenOnBehalfOf() {
        ClientProperties clientProperties = onBehalfOfProperties();
        when(assertionResolver.token()).thenReturn(Optional.of(jwt("sub1").serialize()));
        String firstAccessToken = "first_access_token";
        when(onBehalfOfTokenResponseClient.getTokenResponse(any(OnBehalfOfGrantRequest.class)))
            .thenReturn(accessTokenResponse(firstAccessToken, 60));

        OAuth2AccessTokenResponse oAuth2AccessTokenResponse1 =
            oAuth2AccessTokenService.getAccessToken(clientProperties);
        verify(onBehalfOfTokenResponseClient, times(1)).getTokenResponse(any(OnBehalfOfGrantRequest.class));
        assertThat(oAuth2AccessTokenResponse1).hasNoNullFieldsOrProperties();
        assertThat(oAuth2AccessTokenResponse1.getAccessToken()).isEqualTo("first_access_token");
    }

    @Test
    void getAccessTokenClientCredentials() {
        ClientProperties clientProperties = clientCredentialsProperties();

        String firstAccessToken = "first_access_token";
        when(clientCredentialsTokenResponseClient.getTokenResponse(any(ClientCredentialsGrantRequest.class)))
            .thenReturn(accessTokenResponse(firstAccessToken, 60));

        OAuth2AccessTokenResponse oAuth2AccessTokenResponse1 =
            oAuth2AccessTokenService.getAccessToken(clientProperties);
        verify(clientCredentialsTokenResponseClient, times(1)).getTokenResponse(any(ClientCredentialsGrantRequest.class));
        assertThat(oAuth2AccessTokenResponse1).hasNoNullFieldsOrProperties();
        assertThat(oAuth2AccessTokenResponse1.getAccessToken()).isEqualTo("first_access_token");
    }

    private static ClientProperties exchangeProperties() {
        return exchangeProperties("audience1");
    }

    @Test
    void getAccessTokenOnBehalfOfNoAuthenticatedTokenFound() {
        assertThatExceptionOfType(OAuth2ClientException.class)
            .isThrownBy(() -> oAuth2AccessTokenService.getAccessToken(onBehalfOfProperties()))
            .withMessageContaining("no authenticated jwt token found in validation context, cannot do on-behalf-of");
    }

    @Test
    void getAccessTokenOnBehalfOf_WithCache_MultipleTimes_SameClientConfig() {
        ClientProperties clientProperties = onBehalfOfProperties();

        when(assertionResolver.token()).thenReturn(Optional.of(jwt("sub1").serialize()));

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
        reset(assertionResolver);
        when(assertionResolver.token()).thenReturn(Optional.of(jwt("sub2").serialize()));

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
        ClientProperties clientProperties = clientCredentialsProperties();

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
        clientProperties = clientCredentialsProperties("scope3");

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
        ClientProperties clientProperties = onBehalfOfProperties();
        when(assertionResolver.token()).thenReturn(Optional.of(jwt("sub1").serialize()));

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

    private static JWT jwt(String sub) {
        Instant expiry = LocalDateTime.now().atZone(ZoneId.systemDefault()).plusSeconds(60).toInstant();
        return new PlainJWT(new JWTClaimsSet.Builder()
            .subject(sub)
            .audience("thisapi")
            .issuer("someIssuer")
            .expirationTime(Date.from(expiry))
            .claim("jti", UUID.randomUUID().toString())
            .build());
    }

    private static ClientProperties clientCredentialsProperties() {
        return clientCredentialsProperties("scope1", "scope2");
    }

    private static ClientProperties clientCredentialsProperties(String... scope) {
        return clientProperties("http://token", OAuth2GrantType.CLIENT_CREDENTIALS)
            .toBuilder()
            .scope(Arrays.asList(scope))
            .build();
    }

    private static ClientProperties exchangeProperties(String audience) {
        return clientProperties("http://token", OAuth2GrantType.TOKEN_EXCHANGE)
            .toBuilder()
            .tokenExchange(
                ClientProperties.TokenExchangeProperties.builder()
                    .audience(audience)
                    .build())
            .build();
    }

    @Test
    void getAccessTokenExchange() {
        ClientProperties clientProperties = exchangeProperties();
        when(assertionResolver.token()).thenReturn(Optional.of(jwt("sub1").serialize()));
        String firstAccessToken = "first_access_token";
        when(exchangeTokeResponseClient.getTokenResponse(any(TokenExchangeGrantRequest.class)))
            .thenReturn(accessTokenResponse(firstAccessToken, 60));

        OAuth2AccessTokenResponse oAuth2AccessTokenResponse1 =
            oAuth2AccessTokenService.getAccessToken(clientProperties);
        verify(exchangeTokeResponseClient, times(1)).getTokenResponse(any(TokenExchangeGrantRequest.class));
        assertThat(oAuth2AccessTokenResponse1).hasNoNullFieldsOrProperties();
        assertThat(oAuth2AccessTokenResponse1.getAccessToken()).isEqualTo("first_access_token");
    }

    private static ClientProperties onBehalfOfProperties() {
        return clientProperties("http://token", OAuth2GrantType.JWT_BEARER);
    }

    private static OAuth2AccessTokenResponse accessTokenResponse(String assertion, int expiresIn) {
        return new OAuth2AccessTokenResponse() {
            @Override
            public String getAccessToken() {
                return assertion;
            }

            @Override
            public int getExpiresAt() {
                return Math.toIntExact((Instant.now().plusSeconds(expiresIn).getEpochSecond()));
            }

            @Override
            public int getExpiresIn() {
                return expiresIn;
            }
        };
    }
}
