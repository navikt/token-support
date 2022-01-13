package no.nav.security.token.support.client.spring.oauth2;

import java.net.URI;
import java.util.Optional;

import org.springframework.http.HttpRequest;

import no.nav.security.token.support.client.core.ClientProperties;
import no.nav.security.token.support.client.spring.ClientConfigurationProperties;

/**
 *
 * Default implementation that matcher host in request URL with the registration
 * name. Override for other strategies. Will typically be used with
 * {@link OAuth2ClientRequestInterceptor} or {@link OAuth2ClientExchangeFilterFunction}. Must be registered by the
 * applications themselves, no automatic bean registration
 *
 */
public interface ClientConfigurationPropertiesMatcher {

    @Deprecated(since="1.3.9", forRemoval = true)
    default Optional<ClientProperties> findProperties(ClientConfigurationProperties properties, HttpRequest request) {
        return findProperties(properties,request.getURI());
    }
    default Optional<ClientProperties> findProperties(ClientConfigurationProperties properties, URI uri) {
        return Optional.ofNullable(properties.getRegistration().get(uri.getHost()));

    }
}
