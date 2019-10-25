package no.nav.security.token.support.client.core.oauth2;

import com.github.benmanes.caffeine.cache.Cache;
import lombok.extern.slf4j.Slf4j;
import no.nav.security.token.support.client.core.ClientProperties;
import no.nav.security.token.support.client.core.OAuth2ClientException;
import no.nav.security.token.support.client.core.context.OnBehalfOfAssertionResolver;
import no.nav.security.token.support.client.core.OAuth2GrantType;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

@SuppressWarnings("WeakerAccess")
@Slf4j
public class OAuth2AccessTokenService {

    public static final List<OAuth2GrantType> SUPPORTED_GRANT_TYPES = Arrays.asList(
        OAuth2GrantType.JWT_BEARER,
        OAuth2GrantType.CLIENT_CREDENTIALS);

    private Cache<ClientCredentialsGrantRequest, OAuth2AccessTokenResponse> clientCredentialsGrantCache;
    private Cache<OnBehalfOfGrantRequest, OAuth2AccessTokenResponse> onBehalfOfGrantCache;
    private final OnBehalfOfAssertionResolver assertionResolver;
    private final OnBehalfOfTokenClient onBehalfOfTokenClient;
    private final ClientCredentialsTokenClient clientCredentialsTokenClient;

    public OAuth2AccessTokenService(OnBehalfOfAssertionResolver assertionResolver,
                                    OnBehalfOfTokenClient onBehalfOfTokenClient,
                                    ClientCredentialsTokenClient clientCredentialsTokenClient) {
        this.assertionResolver = assertionResolver;
        this.onBehalfOfTokenClient = onBehalfOfTokenClient;
        this.clientCredentialsTokenClient = clientCredentialsTokenClient;
    }

    public OAuth2AccessTokenResponse getAccessToken(ClientProperties clientProperties) {
        if (clientProperties == null) {
            throw new OAuth2ClientException("ClientProperties cannot be null");
        }
        log.debug("getting access_token with scopes={} for grant={}", clientProperties.getScope(),
            clientProperties.getGrantType());
        if (isGrantType(clientProperties, OAuth2GrantType.JWT_BEARER)) {
            return getAccessTokenOnBehalfOfAuthenticatedJwtToken(clientProperties);
        } else if (isGrantType(clientProperties, OAuth2GrantType.CLIENT_CREDENTIALS)) {
            return getAccessTokenClientCredentials(clientProperties);
        } else {
            throw new OAuth2ClientException(String.format("invalid grant-type=%s from OAuth2ClientConfig.OAuth2Client" +
                    ". grant-type not in supported grant-types (%s)",
                clientProperties.getGrantType().getValue(), SUPPORTED_GRANT_TYPES));
        }
    }

    @SuppressWarnings("unused")
    public Cache<ClientCredentialsGrantRequest, OAuth2AccessTokenResponse> getClientCredentialsGrantCache() {
        return clientCredentialsGrantCache;
    }

    public void setClientCredentialsGrantCache(Cache<ClientCredentialsGrantRequest, OAuth2AccessTokenResponse> clientCredentialsGrantCache) {
        this.clientCredentialsGrantCache = clientCredentialsGrantCache;
    }

    @SuppressWarnings("unused")
    public Cache<OnBehalfOfGrantRequest, OAuth2AccessTokenResponse> getOnBehalfOfGrantCache() {
        return onBehalfOfGrantCache;
    }

    public void setOnBehalfOfGrantCache(Cache<OnBehalfOfGrantRequest, OAuth2AccessTokenResponse> onBehalfOfGrantCache) {
        this.onBehalfOfGrantCache = onBehalfOfGrantCache;
    }

    private OAuth2AccessTokenResponse getAccessTokenOnBehalfOfAuthenticatedJwtToken(ClientProperties clientProperties) {
        final var grantRequest = onBehalfOfGrantRequest(clientProperties);
        return getFromCacheIfEnabled(grantRequest, onBehalfOfGrantCache, onBehalfOfTokenClient::getTokenResponse);
    }

    private OAuth2AccessTokenResponse getAccessTokenClientCredentials(ClientProperties clientProperties) {
        final var grantRequest = new ClientCredentialsGrantRequest(clientProperties);
        return getFromCacheIfEnabled(grantRequest, clientCredentialsGrantCache,
            clientCredentialsTokenClient::getTokenResponse);
    }

    private static <T extends AbstractOAuth2GrantRequest> OAuth2AccessTokenResponse getFromCacheIfEnabled(T grantRequest,
                                                                                                          Cache<T,
                                                                                                              OAuth2AccessTokenResponse> cache,
                                                                                                          Function<T,
                                                                                                              OAuth2AccessTokenResponse> accessTokenResponseClient) {
        if (cache != null) {
            log.debug("cache is enabled so attempt to get from cache or update cache if not present.");
            return cache.get(grantRequest, accessTokenResponseClient);
        } else {
            log.debug("cache is not set, invoke client directly");
            return accessTokenResponseClient.apply(grantRequest);
        }
    }

    private boolean isGrantType(ClientProperties clientProperties,
                                OAuth2GrantType grantType) {
        return Optional.ofNullable(clientProperties)
            .filter(client -> client.getGrantType().equals(grantType))
            .isPresent();
    }

    private OnBehalfOfGrantRequest onBehalfOfGrantRequest(ClientProperties clientProperties) {
        return new OnBehalfOfGrantRequest(clientProperties, assertionResolver.assertion()
            .orElseThrow(() -> new OAuth2ClientException("no authenticated jwt token found in validation context, " +
                "cannot do on-behalf-of")));
    }
}
