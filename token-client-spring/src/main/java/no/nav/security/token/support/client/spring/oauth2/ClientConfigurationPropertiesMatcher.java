package no.nav.security.token.support.client.spring.oauth2;

import java.util.Optional;

import org.springframework.http.HttpRequest;

import no.nav.security.token.support.client.core.ClientProperties;
import no.nav.security.token.support.client.spring.ClientConfigurationProperties;

/**
 *
 * Default implementation that matcher host in request URL with the registration
 * name. Override for other strategies. Will typically be used with
 * {@link OAuth2ClientRequestInterceptor}. Must be registered by the
 * applications themselves, no automatic bean registration
 *
 */
public interface ClientConfigurationPropertiesMatcher {
    default Optional<ClientProperties> findProperties(ClientConfigurationProperties properties, HttpRequest request) {
        return Optional.ofNullable(properties.getRegistration().get(request.getURI().getHost()));
    }
}
