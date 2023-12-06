package no.nav.security.token.support.core.validation

import no.nav.security.token.support.core.exceptions.JwtTokenValidatorException

interface JwtTokenValidator {

    @Throws(JwtTokenValidatorException::class)
    fun assertValidToken(tokenString : String)
}