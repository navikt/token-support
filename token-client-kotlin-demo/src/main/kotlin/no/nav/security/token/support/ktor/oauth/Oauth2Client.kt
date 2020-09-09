package no.nav.security.token.support.ktor.oauth

import io.ktor.util.KtorExperimentalAPI
import no.nav.security.token.support.client.core.context.JwtBearerTokenResolver
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenService
import java.util.*

@KtorExperimentalAPI
class Oauth2Client constructor(
    val oauth2AccessTokenService: OAuth2AccessTokenService,
    val clientProperties: Oauth2ClientProperties
) : JwtBearerTokenResolver {

    fun func() {
        oauth2AccessTokenService.getAccessToken(clientProperties.properties[""])
    }

    override fun token(): Optional<String> {
        TODO("Not yet implemented")
    }
}