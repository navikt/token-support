package no.nav.security.token.support.client.spring.oauth2

import java.net.URI
import no.nav.security.token.support.client.core.ClientProperties
import no.nav.security.token.support.client.spring.ClientConfigurationProperties

/**
 * Implementation of [ClientConfigurationPropertiesMatcher] that matches request URIs
 * based on path prefixes. Each path prefix is associated with a registration name in
 * [ClientConfigurationProperties].
 *
 * Example usage:
 * ```
 * val matcher = PathPrefixClientConfigurationPropertiesMatcher(
 *     listOf(
 *         "/api/resource" to "resource-registration",
 *         "/api/other" to "other-registration"
 *     )
 * )
 * ```
 *
 * The matcher will find the longest matching path prefix for a given URI and return
 * the corresponding [ClientProperties] from the registration map.
 */
class PathPrefixClientConfigurationPropertiesMatcher(
    private val pathPrefixToRegistration: List<Pair<String, String>>
) : ClientConfigurationPropertiesMatcher {

    override fun findProperties(properties: ClientConfigurationProperties, uri: URI): ClientProperties? {
        val path = uri.path ?: return null
        return pathPrefixToRegistration
            .filter { (prefix, _) -> path.startsWith(prefix) }
            .maxByOrNull { (prefix, _) -> prefix.length }
            ?.let { (_, registrationName) -> properties.registration[registrationName] }
    }
}

