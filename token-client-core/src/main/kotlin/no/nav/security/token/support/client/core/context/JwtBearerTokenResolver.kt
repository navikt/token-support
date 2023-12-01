package no.nav.security.token.support.client.core.context

import java.util.Optional

fun interface JwtBearerTokenResolver {
    fun token() : Optional<String>
}