package no.nav.security.token.support.client.spring.oauth2

import no.nav.security.token.support.client.core.ClientProperties
import no.nav.security.token.support.client.spring.ClientConfigurationProperties
import org.springframework.http.HttpRequest
import java.net.URI
import java.util.Optional

/**
 *
 * Default implementation that matcher host in request URL with the registration
 * name. Override for other strategies. Will typically be used with
 * [OAuth2ClientRequestInterceptor]. Must be registered by the
 * applications themselves, no automatic bean registration
 *
 */
interface ClientConfigurationPropertiesMatcher {
    fun findProperties(properties: ClientConfigurationProperties, uri: URI) = Optional.ofNullable(properties.registration[uri.host])
}