package no.nav.security.token.support.ktor.oauth

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import io.ktor.client.*
import io.ktor.config.*
import no.nav.security.token.support.client.core.ClientAuthenticationProperties

class ClientConfig(
    applicationConfig: ApplicationConfig,
    httpClient: HttpClient
) {
    private val cacheConfig: OAuth2CacheConfig =
        with(applicationConfig.config(CACHE_PATH)) {
            OAuth2CacheConfig(
                enabled = propertyToStringOrNull("cache.enabled")?.toBoolean() ?: false,
                maximumSize = propertyToStringOrNull("cache.maximumSize")?.toLong() ?: 0,
                evictSkew = propertyToStringOrNull("cache.evictSkew")?.toLong() ?: 0
            )
        }

    internal val clients: Map<String, OAuth2Client> =
        applicationConfig.configList(CLIENTS_PATH)
            .associate { clientConfig ->
                val wellKnownUrl = clientConfig.propertyToString("well_known_url")
                val clientAuth = ClientAuthenticationProperties(
                    clientConfig.propertyToString("authentication.client_id"),
                    ClientAuthenticationMethod(
                        clientConfig.propertyToString("authentication.client_auth_method")
                    ),
                    clientConfig.propertyToStringOrNull("client_secret"),
                    clientConfig.propertyToStringOrNull("authentication.client_jwk")
                )
                clientConfig.propertyToString(CLIENT_NAME) to OAuth2Client(
                    httpClient = httpClient,
                    wellKnownUrl = wellKnownUrl,
                    clientAuthProperties = clientAuth,
                    cacheConfig = cacheConfig
                )
            }

    companion object CommonConfigurationAttributes {
        const val COMMON_PREFIX = "no.nav.security.jwt.client.registration"
        const val CLIENTS_PATH = "${COMMON_PREFIX}.clients"
        const val CACHE_PATH = "${COMMON_PREFIX}.cache"
        const val CLIENT_NAME = "client_name"
    }
}

internal fun ApplicationConfig.propertyToString(prop: String) = this.property(prop).getString()
internal fun ApplicationConfig.propertyToStringOrNull(prop: String) = this.propertyOrNull(prop)?.getString()
