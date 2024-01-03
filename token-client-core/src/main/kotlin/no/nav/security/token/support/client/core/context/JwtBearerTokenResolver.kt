package no.nav.security.token.support.client.core.context

fun interface JwtBearerTokenResolver {

    fun token() : String?
}