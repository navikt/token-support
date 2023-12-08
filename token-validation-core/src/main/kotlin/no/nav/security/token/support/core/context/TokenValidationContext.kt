package no.nav.security.token.support.core.context

import java.util.Optional
import no.nav.security.token.support.core.jwt.JwtToken

class TokenValidationContext(private val vaidatedTokens : Map<String, JwtToken>) {

    fun getJwtTokenAsOptional(issuerName : String) = jwtToken(issuerName)?.let { Optional.of(it) } ?: Optional.empty()

    val firstValidToken get() = vaidatedTokens.values.firstOrNull()?.let { Optional.of(it) } ?: Optional.empty()
    fun getJwtToken(issuerName : String) = jwtToken(issuerName)

    fun getClaims(issuerName : String) = jwtToken(issuerName)?.jwtTokenClaims ?: throw IllegalArgumentException("No token found for issuer $issuerName")

    val anyValidClaims get() =
        Optional.ofNullable(vaidatedTokens.values
            .map(JwtToken::jwtTokenClaims)
            .firstOrNull())

    fun hasValidToken()  = vaidatedTokens.isNotEmpty()

    fun hasTokenFor(issuerName : String) = getJwtToken(issuerName) != null
    val issuers get() = vaidatedTokens.keys.toList()

    private fun jwtToken(issuerName: String) = vaidatedTokens[issuerName]

    override fun toString() = "TokenValidationContext{issuers=${vaidatedTokens.keys}}"

}