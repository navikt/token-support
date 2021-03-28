package no.nav.security.token.support.client.spring.oauth2;

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
    default ClientProperties findProperties(ClientConfigurationProperties properties, HttpRequest request) {
        return properties.getRegistration().get(request.getURI().getHost());
    }
}
