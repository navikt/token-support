package no.nav.security.token.support.ktor.oauth

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import io.ktor.config.ApplicationConfig
import io.ktor.util.KtorExperimentalAPI
import no.nav.security.token.support.client.core.ClientAuthenticationProperties
import no.nav.security.token.support.client.core.ClientProperties
import no.nav.security.token.support.client.core.OAuth2GrantType
import no.nav.security.token.support.ktor.common.propertyToString
import no.nav.security.token.support.ktor.common.propertyToStringOrNull
import java.net.URI

@KtorExperimentalAPI
class OAuth2ClientProperties(
    applicationConfig: ApplicationConfig
) {

    private val clients: Map<String, ClientProperties> =
        applicationConfig.configList(REGISTRATION_PATH)
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

    private val cache: Map<String, OAuth2Cache> =
        applicationConfig.configList(REGISTRATION_PATH)
            .associate { clientConfig ->
                clientConfig.propertyToString(CLIENT_NAME) to OAuth2Cache(
                    enabled = clientConfig.propertyToStringOrNull("cache.enabled")?.toBoolean() ?: false,
                    maximumSize = clientConfig.propertyToStringOrNull("cache.maximumSize")?.toLong() ?: 0,
                    evictSkew = clientConfig.propertyToStringOrNull("cache.evictSkew")?.toLong() ?: 0
                )
            }

    fun getConfig(client: String) = this.clients[client]
        ?: throw RuntimeException("$client do not exist in configuration")

    fun getCache(client: String) = this.cache[client]
        ?: throw RuntimeException("$client do not exist in configuration")


    companion object CommonConfigurationAttributes {
        const val REGISTRATION_PATH = "no.nav.security.jwt.client.registration.clients"
        const val CLIENT_NAME = "client_name"
    }
}