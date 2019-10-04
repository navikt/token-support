package no.nav.security.token.support.oauth2.client;

import com.github.benmanes.caffeine.cache.Cache;
import lombok.extern.slf4j.Slf4j;
import no.nav.security.token.support.core.context.TokenValidationContextHolder;
import no.nav.security.token.support.core.jwt.JwtToken;
import no.nav.security.token.support.oauth2.ClientConfigurationProperties;
import no.nav.security.token.support.oauth2.OAuth2ClientException;
import no.nav.security.token.support.oauth2.OAuth2GrantType;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

@Slf4j
public class OAuth2AccessTokenService {

    public static final List<OAuth2GrantType> SUPPORTED_GRANT_TYPES = Arrays.asList(
        OAuth2GrantType.JWT_BEARER,
        OAuth2GrantType.CLIENT_CREDENTIALS);

    private Cache<ClientCredentialsGrantRequest, OAuth2AccessTokenResponse> clientCredentialsGrantCache;
    private Cache<OnBehalfOfGrantRequest, OAuth2AccessTokenResponse> onBehalfOfGrantCache;

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
        if (clientProperties == null) {
            throw new OAuth2ClientException("ClientConfigurationProperties.ClientProperties cannot be null");
        }
        log.debug("getting access_token with scopes={} for grant={}", clientProperties.getScope(), clientProperties.getGrantType());
        if (isGrantType(clientProperties, OAuth2GrantType.JWT_BEARER)) {
            return getAccessTokenOnBehalfOfAuthenticatedJwtToken(clientProperties);
        } else if (isGrantType(clientProperties, OAuth2GrantType.CLIENT_CREDENTIALS)) {
            return getAccessTokenClientCredentials(clientProperties);
        } else {
            throw new OAuth2ClientException(String.format("invalid grant-type=%s from OAuth2ClientConfig.OAuth2Client. grant-type not in supported grant-types (%s)",
                clientProperties.getGrantType().getValue(), SUPPORTED_GRANT_TYPES));
        }
    }

    public void setClientCredentialsGrantCache(Cache<ClientCredentialsGrantRequest, OAuth2AccessTokenResponse> clientCredentialsGrantCache) {
        this.clientCredentialsGrantCache = clientCredentialsGrantCache;
    }

    public void setOnBehalfOfGrantCache(Cache<OnBehalfOfGrantRequest, OAuth2AccessTokenResponse> onBehalfOfGrantCache) {
        this.onBehalfOfGrantCache = onBehalfOfGrantCache;
    }

    private OAuth2AccessTokenResponse getAccessTokenOnBehalfOfAuthenticatedJwtToken(ClientConfigurationProperties.ClientProperties clientProperties) {
        OnBehalfOfGrantRequest onBehalfOfGrantRequest = onBehalfOfGrantRequest(clientProperties);
        return get(onBehalfOfGrantRequest, onBehalfOfGrantCache, onBehalfOfTokenResponseClient::getTokenResponse);
    }

    private OAuth2AccessTokenResponse getAccessTokenClientCredentials(ClientConfigurationProperties.ClientProperties clientProperties) {
        ClientCredentialsGrantRequest clientCredentialsGrantRequest = new ClientCredentialsGrantRequest(clientProperties);
        return get(clientCredentialsGrantRequest, clientCredentialsGrantCache, clientCredentialsTokenResponseClient::getTokenResponse);
    }

    private static <T extends AbstractOAuth2GrantRequest> OAuth2AccessTokenResponse get(T grantRequest,
                                                                                 Cache<T, OAuth2AccessTokenResponse> cache,
                                                                                 Function<T, OAuth2AccessTokenResponse> function) {
        if (cache != null) {
            log.debug("cache is enabled so attempt to get from cache or update cache if not present.");
            return cache.get(grantRequest, function);
        } else {
            log.debug("cache is not set, invoke client directly");
            return function.apply(grantRequest);
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
