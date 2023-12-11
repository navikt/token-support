package no.nav.security.token.support.core.context

import java.util.Optional
import no.nav.security.token.support.core.jwt.JwtToken

class TokenValidationContext(private val validatedTokens : Map<String, JwtToken>) {

    fun getJwtTokenAsOptional(issuerName : String) = jwtToken(issuerName)?.let { Optional.of(it) } ?: Optional.empty()

    val firstValidToken get() = validatedTokens.values.firstOrNull()
    fun getJwtToken(issuerName : String) = jwtToken(issuerName)

    fun getClaims(issuerName : String) = jwtToken(issuerName)?.jwtTokenClaims ?: throw IllegalArgumentException("No token found for issuer $issuerName")

    val anyValidClaims get() =
        Optional.ofNullable(validatedTokens.values
            .map(JwtToken::jwtTokenClaims)
            .firstOrNull())

    fun hasValidToken()  = validatedTokens.isNotEmpty()

    fun hasTokenFor(issuerName : String) = getJwtToken(issuerName) != null
    val issuers get() = validatedTokens.keys.toList()

    private fun jwtToken(issuerName: String) = validatedTokens[issuerName]

    override fun toString() = "TokenValidationContext{issuers=${validatedTokens.keys}}"

}