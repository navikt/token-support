package no.nav.security.token.support.client.spring.oauth2

import java.net.URI
import java.net.URI.create
import no.nav.security.token.support.client.spring.ClientConfigurationProperties

/**
 *
 * Default implementation that matcher host in request URL with the registration
 * name. Override for other strategies. Will typically be used with
 * [OAuth2ClientRequestInterceptor]. Must be registered by the
 * applications themselves, no automatic bean registration
 *
 */
interface ClientConfigurationPropertiesMatcher {

    fun findProperties(properties: ClientConfigurationProperties, uri: String) = findProperties(properties, create(uri))

    fun findProperties(properties: ClientConfigurationProperties, uri: URI) =
        uri.host.split(".").firstOrNull()?.let {
            properties.registration[it]
    }
}