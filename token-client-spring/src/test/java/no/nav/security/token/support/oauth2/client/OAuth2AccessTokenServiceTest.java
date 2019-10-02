package no.nav.security.token.support.oauth2.client;

import no.nav.security.token.support.core.context.TokenValidationContext;
import no.nav.security.token.support.core.context.TokenValidationContextHolder;
import no.nav.security.token.support.core.jwt.JwtToken;
import no.nav.security.token.support.oauth2.ClientConfigurationProperties;
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

class OAuth2AccessTokenServiceTest {

    @Mock
    private OnBehalfOfTokenResponseClient onBehalfOfTokenResponseClient;
    @Mock
    private ClientCredentialsTokenResponseClient clientCredentialsTokenResponseClient;
    @Mock
    private TokenValidationContextHolder tokenValidationContextHolder;

    private OAuth2AccessTokenService oAuth2AccessTokenService;

    @BeforeEach
    void setup() {
        MockitoAnnotations.initMocks(this);
        oAuth2AccessTokenService = new OAuth2AccessTokenService(
            tokenValidationContextHolder,
            onBehalfOfTokenResponseClient,
            clientCredentialsTokenResponseClient);


    }

    @Test
    void getAccessTokenOnBehalfOf() {
        setupTokenValidationContext();

        when(onBehalfOfTokenResponseClient.getTokenResponse(any(OnBehalfOfGrantRequest.class)))
            .thenReturn(new OAuth2AccessTokenResponse() {
                @Override
                public String getAccessToken() {
                    return "on_behalf_of_token";
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

        OAuth2AccessTokenResponse oAuth2AccessTokenResponse = oAuth2AccessTokenService.getAccessToken(oAuth2Client());
        assertThat(oAuth2AccessTokenResponse).hasNoNullFieldsOrProperties();
    }

    @Test
    void getAccessTokenClientCredentials() {
        ClientConfigurationProperties.ClientProperties clientProperties = oAuth2Client();
        clientProperties.setGrantType(OAuth2GrantType.CLIENT_CREDENTIALS);

        when(clientCredentialsTokenResponseClient.getTokenResponse(any(ClientCredentialsGrantRequest.class)))
            .thenReturn(new OAuth2AccessTokenResponse() {
                @Override
                public String getAccessToken() {
                    return "client_credentials_token";
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

        OAuth2AccessTokenResponse oAuth2AccessTokenResponse = oAuth2AccessTokenService.getAccessToken(clientProperties);
        assertThat(oAuth2AccessTokenResponse).hasNoNullFieldsOrProperties();
        assertThat(oAuth2AccessTokenResponse.getAccessToken()).contains("client_credentials_token");
    }

    @Test
    void noAuthenticatedTokenFound() {
        assertThatExceptionOfType(OAuth2ClientException.class)
            .isThrownBy(() -> oAuth2AccessTokenService.getAccessToken(oAuth2Client()))
            .withMessageContaining("no authenticated jwt token found in validation context, cannot do on-behalf-of");
    }

    @Test
    void unsupportedGrantType() {
        setupTokenValidationContext();
        ClientConfigurationProperties.ClientProperties clientProperties = oAuth2Client();
        clientProperties.setGrantType(new OAuth2GrantType("someGrantNotSupported"));
        assertThatExceptionOfType(OAuth2ClientException.class)
            .isThrownBy(() -> oAuth2AccessTokenService.getAccessToken(clientProperties))
            .withMessageContaining("invalid grant-type");
    }

    private void setupTokenValidationContext() {
        Map<String, JwtToken> map = new HashMap<>();
        map.put("issuer1", new JwtToken(createJwt()));
        when(tokenValidationContextHolder.getTokenValidationContext()).thenReturn(new TokenValidationContext(map));
    }

    private ClientConfigurationProperties.ClientProperties oAuth2Client() {
        ClientConfigurationProperties.ClientProperties clientProperties = new ClientConfigurationProperties.ClientProperties();
        clientProperties.setClientAuthMethod("client_secret_basic");
        clientProperties.setClientId("myid");
        clientProperties.setClientSecret("mysecret");
        clientProperties.setScope(Arrays.asList("scope1", "scope2"));
        //create new object instead of using OAuth2GrantType.JWT_BEARER to test equality
        clientProperties.setGrantType(new OAuth2GrantType("urn:ietf:params:oauth:grant-type:jwt-bearer"));
        clientProperties.setTokenEndpointUrl(URI.create("http://localhost/token"));
        return clientProperties;
    }
}
