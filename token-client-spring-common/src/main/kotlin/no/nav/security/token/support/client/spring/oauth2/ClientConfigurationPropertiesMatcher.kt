package no.nav.security.token.support.client.spring.oauth2

import no.nav.security.token.support.client.spring.ClientConfigurationProperties
import java.net.URI
import java.util.*

/**
 *
 * Default implementation that matcher host in request URL with the registration
 * name. Override for other strategies. Will typically be used with
 * [OAuth2ClientRequestInterceptor]. Must be registered by the
 * applications themselves, no automatic bean registration
 *
 */
interface ClientConfigurationPropertiesMatcher {
    fun findProperties(properties: ClientConfigurationProperties, uri: URI) = Optional.ofNullable(properties.registration[uri.host.split(".").first()])
}