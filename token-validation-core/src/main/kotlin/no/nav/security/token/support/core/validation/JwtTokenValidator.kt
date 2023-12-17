package no.nav.security.token.support.core.validation

interface JwtTokenValidator {

    fun assertValidToken(tokenString : String)
}