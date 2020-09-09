package no.nav.security.token.support.ktor.oauth

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import io.ktor.config.ApplicationConfig
import io.ktor.util.KtorExperimentalAPI
import no.nav.security.token.support.client.core.ClientAuthenticationProperties
import no.nav.security.token.support.client.core.ClientProperties
import no.nav.security.token.support.client.core.OAuth2GrantType
import java.net.URI

@KtorExperimentalAPI
class Oauth2ClientProperties(
    applicationConfig: ApplicationConfig
) {

    val properties: Map<String, ClientProperties> = applicationConfig.configList("no.nav.security.jwt.client.registration")
        .associate { clientConfig ->
            val wellKnownUrl = clientConfig.propertyOrNull("well_known_url")?.getString()
            val resourceUrl = clientConfig.propertyOrNull("resource_url")?.getString()
            clientConfig.property("client_name").getString() to ClientProperties(
                URI(clientConfig.property("token_endpoint_url").getString()),
                if (wellKnownUrl != null) URI(wellKnownUrl) else wellKnownUrl,
                OAuth2GrantType(clientConfig.property("grant_type").getString()),
                clientConfig.propertyOrNull("scope")?.getString()?.split(","),
                ClientAuthenticationProperties(
                    clientConfig.property("client_id").getString(),
                    ClientAuthenticationMethod(clientConfig.property("client_auth_method").getString()),
                    clientConfig.propertyOrNull("client_secret")?.getString(),
                    clientConfig.propertyOrNull("client_jwk")?.getString()
                ),
                if (resourceUrl != null) URI(resourceUrl) else resourceUrl,
                ClientProperties.TokenExchangeProperties(
                    clientConfig.property("audience").getString(),
                    clientConfig.propertyOrNull("resource")?.getString()
                )
            )
        }
}