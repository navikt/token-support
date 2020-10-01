package no.nav.security.token.support.ktor.oauth

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import io.ktor.config.ApplicationConfig
import io.ktor.util.KtorExperimentalAPI
import no.nav.security.token.support.client.core.ClientAuthenticationProperties
import no.nav.security.token.support.client.core.ClientProperties
import no.nav.security.token.support.client.core.OAuth2GrantType
import no.nav.security.token.support.ktor.model.OAuth2Cache
import no.nav.security.token.support.ktor.utils.propertyToString
import no.nav.security.token.support.ktor.utils.propertyToStringOrNull
import java.net.URI

@KtorExperimentalAPI
class ClientPropertiesConfig(
    applicationConfig: ApplicationConfig
) {

    internal val clientConfig: Map<String, ClientProperties> =
        applicationConfig.configList(CLIENTS_PATH)
            .associate { clientConfig ->
                val wellKnownUrl = clientConfig.propertyToStringOrNull("well_known_url")
                val resourceUrl = clientConfig.propertyToStringOrNull("resource_url")
                clientConfig.propertyToString(CLIENT_NAME) to ClientProperties(
                    URI(clientConfig.propertyToString("token_endpoint_url")),
                    wellKnownUrl?.let { URI(it) },
                    OAuth2GrantType(clientConfig.propertyToString("grant_type")),
                    clientConfig.propertyToStringOrNull("scope")?.split(","),
                    ClientAuthenticationProperties(
                        clientConfig.propertyToString("authentication.client_id"),
                        ClientAuthenticationMethod(
                            clientConfig.propertyToString("authentication.client_auth_method")
                        ),
                        clientConfig.propertyToStringOrNull("client_secret"),
                        clientConfig.propertyToStringOrNull("authentication.client_jwk")
                    ),
                    resourceUrl?.let { URI(it) },
                    ClientProperties.TokenExchangeProperties(
                        clientConfig.propertyToStringOrNull("token-exchange.audience") ?: "",
                        clientConfig.propertyToStringOrNull("token-exchange.resource")
                    )
                )
            }

    internal val cacheConfig: OAuth2Cache =
        with(applicationConfig.config(CACHE_PATH)) {
            OAuth2Cache(
                enabled = propertyToStringOrNull("cache.enabled")?.toBoolean() ?: false,
                maximumSize = propertyToStringOrNull("cache.maximumSize")?.toLong() ?: 0,
                evictSkew = propertyToStringOrNull("cache.evictSkew")?.toLong() ?: 0
            )
        }

    companion object CommonConfigurationAttributes {
        const val COMMON_PREFIX = "no.nav.security.jwt.client.registration"
        const val CLIENTS_PATH = "${COMMON_PREFIX}.clients"
        const val CACHE_PATH = "${COMMON_PREFIX}.cache"
        const val CLIENT_NAME = "client_name"
    }
}