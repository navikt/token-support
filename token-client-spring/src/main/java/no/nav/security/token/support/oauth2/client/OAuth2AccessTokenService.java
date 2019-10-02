package no.nav.security.token.support.oauth2.client;

import no.nav.security.token.support.core.context.TokenValidationContextHolder;
import no.nav.security.token.support.core.jwt.JwtToken;
import no.nav.security.token.support.oauth2.ClientConfigurationProperties;
import no.nav.security.token.support.oauth2.OAuth2ClientException;
import no.nav.security.token.support.oauth2.OAuth2GrantType;

import java.util.Arrays;
import java.util.Optional;

public class OAuth2AccessTokenService {

    private final TokenValidationContextHolder contextHolder;
    private final OnBehalfOfTokenResponseClient onBehalfOfTokenResponseClient;
    private final ClientCredentialsTokenResponseClient clientCredentialsTokenResponseClient;

    public OAuth2AccessTokenService(TokenValidationContextHolder contextHolder,
                                    OnBehalfOfTokenResponseClient onBehalfOfTokenResponseClient,
                                    ClientCredentialsTokenResponseClient clientCredentialsTokenResponseClient) {
        this.contextHolder = contextHolder;
        this.onBehalfOfTokenResponseClient = onBehalfOfTokenResponseClient;
        this.clientCredentialsTokenResponseClient = clientCredentialsTokenResponseClient;
    }

    public OAuth2AccessTokenResponse getAccessToken(ClientConfigurationProperties.ClientProperties clientProperties) {
        if(clientProperties == null) {
            throw new OAuth2ClientException("ClientConfigurationProperties.ClientProperties cannot be null");
        }
        if (isGrantType(clientProperties, OAuth2GrantType.JWT_BEARER)) {
            return onBehalfOfTokenResponseClient.getTokenResponse(onBehalfOfGrantRequest(clientProperties));
        } else if (isGrantType(clientProperties, OAuth2GrantType.CLIENT_CREDENTIALS)) {
            return clientCredentialsTokenResponseClient.getTokenResponse(new ClientCredentialsGrantRequest(clientProperties));
        } else {
            throw new OAuth2ClientException(String.format("invalid grant-type=%s from OAuth2ClientConfig.OAuth2Client. grant-type not in supported grant-types (%s)",
                clientProperties.getGrantType().getValue(), Arrays.asList(OAuth2GrantType.JWT_BEARER, OAuth2GrantType.CLIENT_CREDENTIALS)));
        }
    }

    private boolean isGrantType(ClientConfigurationProperties.ClientProperties clientProperties, OAuth2GrantType grantType) {
       return Optional.ofNullable(clientProperties)
            .filter(client -> client.getGrantType().equals(grantType))
            .isPresent();
    }

    private OnBehalfOfGrantRequest onBehalfOfGrantRequest(ClientConfigurationProperties.ClientProperties clientProperties) {
        return new OnBehalfOfGrantRequest(clientProperties, authenticatedJwtToken()
            .orElseThrow(() -> new OAuth2ClientException("no authenticated jwt token found in validation context, cannot do on-behalf-of")));
    }

    private Optional<String> authenticatedJwtToken() {
        return contextHolder.getTokenValidationContext() != null ?
            contextHolder.getTokenValidationContext().getFirstValidToken()
                .map(JwtToken::getTokenAsString) :
            Optional.empty();
    }
}
