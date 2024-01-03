package no.nav.security.token.support.ktor.oauth

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import io.ktor.client.HttpClient
import io.ktor.server.config.ApplicationConfig
import no.nav.security.token.support.client.core.ClientAuthenticationProperties

class ClientConfig(applicationConfig: ApplicationConfig, httpClient: HttpClient) {
    private val cacheConfig =
        with(applicationConfig.config(CACHE_PATH)) {
            OAuth2CacheConfig(propertyToStringOrNull("cache.enabled")?.toBoolean() ?: false, propertyToStringOrNull("cache.maximumSize")?.toLong() ?: 0, propertyToStringOrNull("cache.evictSkew")?.toLong() ?: 0)
        }

    internal val clients =
        applicationConfig.configList(CLIENTS_PATH)
            .associate {
                val wellKnownUrl = it.propertyToString("well_known_url")
                val clientAuth = ClientAuthenticationProperties(
                    it.propertyToString("authentication.client_id"),
                    ClientAuthenticationMethod(it.propertyToString("authentication.client_auth_method")),
                    it.propertyToStringOrNull("client_secret"),
                    it.propertyToStringOrNull("authentication.client_jwk"))
                it.propertyToString(CLIENT_NAME) to OAuth2Client(httpClient, wellKnownUrl, clientAuth, cacheConfig)
            }

    companion object CommonConfigurationAttributes {
        const val COMMON_PREFIX = "no.nav.security.jwt.client.registration"
        const val CLIENTS_PATH = "${COMMON_PREFIX}.clients"
        const val CACHE_PATH = "${COMMON_PREFIX}.cache"
        const val CLIENT_NAME = "client_name"
    }
}

internal fun ApplicationConfig.propertyToString(prop: String) = property(prop).getString()
internal fun ApplicationConfig.propertyToStringOrNull(prop: String) = propertyOrNull(prop)?.getString()