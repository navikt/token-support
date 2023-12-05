package no.nav.security.token.support.core.context

import java.util.Optional
import no.nav.security.token.support.core.jwt.JwtToken

class TokenValidationContext(private val issuerShortNameValidatedTokenMap : Map<String, JwtToken>) {

    fun getJwtTokenAsOptional(issuerName : String) = jwtToken(issuerName)?.let { Optional.of(it) } ?: Optional.empty()

    val firstValidToken get() = issuerShortNameValidatedTokenMap.values.firstOrNull()?.let { Optional.of(it) } ?: Optional.empty()
    fun getJwtToken(issuerName : String) = jwtToken(issuerName)

    override fun toString() = "TokenValidationContext{issuers=${issuerShortNameValidatedTokenMap.keys}}"

    fun getClaims(issuerName : String) = jwtToken(issuerName)?.jwtTokenClaims ?: throw IllegalArgumentException("no token found for issuer $issuerName")

    val anyValidClaims get() = issuerShortNameValidatedTokenMap.values
        .map { it.jwtTokenClaims }
        .firstOrNull()?.let {
            Optional.of(it)
        } ?: Optional.empty()

    fun hasValidToken()  = issuerShortNameValidatedTokenMap.isNotEmpty()

    fun hasTokenFor(issuerName : String) = getJwtToken(issuerName) != null

    val issuers get() = issuerShortNameValidatedTokenMap.keys.toList()

    private fun jwtToken(issuerName: String) = issuerShortNameValidatedTokenMap[issuerName]

}