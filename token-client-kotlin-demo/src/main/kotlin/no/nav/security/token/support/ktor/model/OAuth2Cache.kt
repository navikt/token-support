package no.nav.security.token.support.ktor.model

data class OAuth2Cache(
    val enabled: Boolean,
    val maximumSize: Long,
    val evictSkew: Long
)