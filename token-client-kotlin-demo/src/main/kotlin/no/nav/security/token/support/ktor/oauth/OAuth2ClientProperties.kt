package no.nav.security.token.support.ktor.oauth

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import io.ktor.config.ApplicationConfig
import io.ktor.util.KtorExperimentalAPI
import no.nav.security.token.support.client.core.ClientAuthenticationProperties
import no.nav.security.token.support.client.core.ClientProperties
import no.nav.security.token.support.client.core.OAuth2GrantType
import java.net.URI

@KtorExperimentalAPI
class OAuth2ClientProperties(
    applicationConfig: ApplicationConfig
) {

    val clients: Map<String, ClientProperties> =
        applicationConfig.configList(REGISTRATION_PATH)
            .associate { clientConfig ->
                val wellKnownUrl = clientConfig.propertyToStringOrNull(WELL_KNOWN_URL)
                val resourceUrl = clientConfig.propertyToStringOrNull(RESOURCE_URL)
                clientConfig.propertyToString(CLIENT_NAME) to ClientProperties(
                    URI(clientConfig.propertyToString(TOKEN_ENDPOINT_URL)),
                    wellKnownUrl?.let { URI(it) },
                    OAuth2GrantType(clientConfig.propertyToString(GRANT_TYPE)),
                    clientConfig.propertyToStringOrNull(SCOPE)?.split(","),
                    ClientAuthenticationProperties(
                        clientConfig.propertyToString(AUTHENTICATION_CLIENT_ID),
                        ClientAuthenticationMethod(
                            clientConfig.propertyToString(AUTHENTICATION_CLIENT_AUTH_METHOD)
                        ),
                        clientConfig.propertyToStringOrNull(CLIENT_SECRET),
                        clientConfig.propertyToStringOrNull(AUTHENTICATION_CLIENT_JWK)
                    ),
                    resourceUrl?.let { URI(it) },
                    ClientProperties.TokenExchangeProperties(
                        clientConfig.propertyToStringOrNull(TOKEN_EXCHANGE_AUDIENCE) ?: "",
                        clientConfig.propertyToStringOrNull(TOKEN_EXCHANGE_RESOURCE)
                    )
                )
            }

    private fun ApplicationConfig.propertyToString(prop: String) = this.property(prop).getString()

    private fun ApplicationConfig.propertyToStringOrNull(prop: String) = this.propertyOrNull(prop)?.getString()

    companion object ConfigurationAttributes {
        const val REGISTRATION_PATH = "no.nav.security.jwt.client.registration.clients"
        const val WELL_KNOWN_URL = "well_known_url"
        const val RESOURCE_URL = "resource_url"
        const val TOKEN_ENDPOINT_URL = "token_endpoint_url"
        const val GRANT_TYPE = "grant_type"
        const val SCOPE = "scope"
        const val CLIENT_SECRET = "client_secret"
        const val CLIENT_NAME = "client_name"
        const val AUTHENTICATION_CLIENT_JWK = "authentication.client_jwk"
        const val AUTHENTICATION_CLIENT_ID = "authentication.client_id"
        const val AUTHENTICATION_CLIENT_AUTH_METHOD = "authentication.client_auth_method"
        const val TOKEN_EXCHANGE_AUDIENCE = "token.exchange.audience"
        const val TOKEN_EXCHANGE_RESOURCE = "token.exchange.resource"
    }
}