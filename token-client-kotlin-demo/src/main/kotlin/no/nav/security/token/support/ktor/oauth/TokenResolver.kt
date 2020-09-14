package no.nav.security.token.support.ktor.oauth

import no.nav.security.token.support.client.core.context.JwtBearerTokenResolver
import no.nav.security.token.support.ktor.TokenValidationContextPrincipal
import java.util.Optional

class TokenResolver: JwtBearerTokenResolver {
    var tokenPrincipal: TokenValidationContextPrincipal? = null

    override fun token(): Optional<String> {
        return tokenPrincipal?.context?.firstValidToken?.map { it.tokenAsString } ?: Optional.empty()
    }
}