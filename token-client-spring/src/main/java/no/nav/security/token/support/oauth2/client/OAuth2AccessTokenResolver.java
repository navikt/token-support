package no.nav.security.token.support.oauth2.client;

import no.nav.security.token.support.core.context.TokenValidationContextHolder;
import no.nav.security.token.support.core.jwt.JwtToken;
import no.nav.security.token.support.oauth2.OAuth2ClientConfig;
import no.nav.security.token.support.oauth2.OAuth2ClientException;
import no.nav.security.token.support.oauth2.OAuth2GrantType;

import java.util.Arrays;
import java.util.Optional;

public class OAuth2AccessTokenResolver {

    private final TokenValidationContextHolder contextHolder;
    private final OnBehalfOfTokenResponseClient onBehalfOfTokenResponseClient;

    public OAuth2AccessTokenResolver(TokenValidationContextHolder contextHolder,
                                     OnBehalfOfTokenResponseClient onBehalfOfTokenResponseClient) {
        this.contextHolder = contextHolder;
        this.onBehalfOfTokenResponseClient = onBehalfOfTokenResponseClient;
    }

    public OAuth2AccessTokenResponse getAccessToken(OAuth2ClientConfig.OAuth2Client oAuth2Client) {
        if (isGrantType(oAuth2Client, OAuth2GrantType.JWT_BEARER)) {
            return onBehalfOfTokenResponseClient.getTokenResponse(onBehalfOfGrantRequest(oAuth2Client));
        } else if (isGrantType(oAuth2Client, OAuth2GrantType.CLIENT_CREDENTIALS)) {
            //TODO
            throw new OAuth2ClientException("grant-type not implemented yet");
        } else {
            throw new OAuth2ClientException(String.format("invalid grant-type from OAuth2ClientConfig.OAuth2Client. grant-type not set or not in supported grant-types (%s)",
                Arrays.asList(OAuth2GrantType.JWT_BEARER, OAuth2GrantType.CLIENT_CREDENTIALS)));
        }
    }

    private boolean isGrantType(OAuth2ClientConfig.OAuth2Client oAuth2Client, OAuth2GrantType grantType) {
        return Optional.ofNullable(oAuth2Client)
            .filter(client -> client.getGrantType().equals(grantType))
            .isPresent();
    }

    private OnBehalfOfGrantRequest onBehalfOfGrantRequest(OAuth2ClientConfig.OAuth2Client oAuth2Client) {
        return new OnBehalfOfGrantRequest(oAuth2Client, authenticatedJwtToken()
            .orElseThrow(() -> new OAuth2ClientException("no authenticated jwt token found in validation context, cannot do on-behalf-of")));
    }

    private Optional<String> authenticatedJwtToken() {
        return contextHolder.getTokenValidationContext() != null ?
            contextHolder.getTokenValidationContext().getFirstValidToken()
                .map(JwtToken::getTokenAsString) :
            Optional.empty();
    }
}
