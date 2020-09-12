package no.nav.security.token.support.ktor.oauth

import no.nav.security.token.support.client.core.context.JwtBearerTokenResolver
import no.nav.security.token.support.ktor.jwt.ClientAssertion
import java.util.Optional

class TokenResolver(
    private val client: ClientAssertion
) : JwtBearerTokenResolver {

    // Override default client_assertion jwt, with specified Idp jwt
    override fun token(): Optional<String> {
        return Optional.of(client.assertion())
    }
}