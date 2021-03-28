package no.nav.security.token.support.client.spring.oauth2;

import java.util.Optional;

import org.springframework.http.HttpRequest;

import no.nav.security.token.support.client.core.ClientProperties;
import no.nav.security.token.support.client.spring.ClientConfigurationProperties;

/**
 *
 * Default implementasjon matcher host i request med registration navn. Override
 * for andre strategier
 *
 */
public interface ClientConfigurationPropertiesMatcher {
    default Optional<ClientProperties> findProperties(ClientConfigurationProperties properties, HttpRequest request) {
        return Optional.ofNullable(properties.getRegistration().get(request.getURI().getHost()));
    }
}
