package no.nav.security.token.support.oauth2.client;

import no.nav.security.token.support.core.context.TokenValidationContext;
import no.nav.security.token.support.core.context.TokenValidationContextHolder;
import no.nav.security.token.support.core.jwt.JwtToken;
import no.nav.security.token.support.oauth2.OAuth2ClientConfig;
import no.nav.security.token.support.oauth2.OAuth2ClientException;
import no.nav.security.token.support.oauth2.OAuth2GrantType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.net.URI;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static no.nav.security.token.support.oauth2.client.TestUtils.createJwt;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

class OAuth2AccessTokenResolverTest {

    @Mock
    private OnBehalfOfTokenResponseClient onBehalfOfTokenResponseClient;
    @Mock
    private TokenValidationContextHolder tokenValidationContextHolder;

    private OAuth2AccessTokenResolver oAuth2AccessTokenResolver;

    @BeforeEach
    void setup(){
        MockitoAnnotations.initMocks(this);
        oAuth2AccessTokenResolver = new OAuth2AccessTokenResolver(tokenValidationContextHolder, onBehalfOfTokenResponseClient);
        when(onBehalfOfTokenResponseClient.getTokenResponse(any(OnBehalfOfGrantRequest.class)))
            .thenReturn(new OAuth2AccessTokenResponse(){
                @Override
                public String getAccessToken() {
                    return "super.getAccessToken();";
                }

                @Override
                public int getExpiresAt() {
                    return 1234567;
                }

                @Override
                public int getExpiresIn() {
                    return 3600;
                }
            });
    }

    @Test
    void getAccessTokenOnBehalfOf(){
        setupTokenValidationContext();
        OAuth2AccessTokenResponse oAuth2AccessTokenResponse = oAuth2AccessTokenResolver.getAccessToken(oAuth2Client());
        assertThat(oAuth2AccessTokenResponse).hasNoNullFieldsOrProperties();
    }

    @Test
    void noAuthenticatedTokenFound(){
        assertThatExceptionOfType(OAuth2ClientException.class)
            .isThrownBy(() ->  oAuth2AccessTokenResolver.getAccessToken(oAuth2Client()))
            .withMessageContaining("no authenticated jwt token found in validation context, cannot do on-behalf-of");
    }

    @Test
    void unsupportedGrantType(){
        setupTokenValidationContext();
        OAuth2ClientConfig.OAuth2Client oAuth2Client = oAuth2Client();
        oAuth2Client.setGrantType(new OAuth2GrantType("someGrantNotSupported"));
        assertThatExceptionOfType(OAuth2ClientException.class)
            .isThrownBy(() ->  oAuth2AccessTokenResolver.getAccessToken(oAuth2Client))
            .withMessageContaining("invalid grant-type");
    }

    private void setupTokenValidationContext(){
        Map<String, JwtToken> map = new HashMap<>();
        map.put("issuer1", new JwtToken(createJwt()));
        when(tokenValidationContextHolder.getTokenValidationContext()).thenReturn(new TokenValidationContext(map));
    }

    private OAuth2ClientConfig.OAuth2Client oAuth2Client() {
        OAuth2ClientConfig.OAuth2Client oAuth2Client = new OAuth2ClientConfig.OAuth2Client();
        oAuth2Client.setClientAuthMethod("client_secret_basic");
        oAuth2Client.setClientId("myid");
        oAuth2Client.setClientSecret("mysecret");
        oAuth2Client.setScope(Arrays.asList("scope1", "scope2"));
        oAuth2Client.setGrantType(OAuth2GrantType.JWT_BEARER);
        oAuth2Client.setTokenEndpointUrl(URI.create("http://localhost/token"));
        return oAuth2Client;
    }
}
