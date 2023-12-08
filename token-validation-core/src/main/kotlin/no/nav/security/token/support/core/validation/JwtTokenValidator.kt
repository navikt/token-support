package no.nav.security.token.support.core.validation

import no.nav.security.token.support.core.exceptions.JwtTokenValidatorException

interface JwtTokenValidator {

    fun assertValidToken(tokenString : String)
}