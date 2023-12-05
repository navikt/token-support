package no.nav.security.token.support.core.jwt

import com.nimbusds.jwt.JWTClaimsSet
import java.text.ParseException
import java.util.Date

class JwtTokenClaims(private val claimSet : JWTClaimsSet) {

    val issuer  = claimSet.issuer
    val expirationTime  = claimSet.expirationTime
    val subject = claimSet.subject
    val allClaims  = claimSet.claims


    fun get(name : String) = claimSet.getClaim(name)
    fun getStringClaim(name : String) = runCatching { claimSet.getStringClaim(name) }.getOrElse { throw RuntimeException(it) }
    fun getAsList(name : String) = runCatching { claimSet.getStringListClaim(name) }.getOrElse { throw RuntimeException(it) }

    fun containsClaim(name: String?, value: String) =
        when (val claim = claimSet.getClaim(name)) {
            is String -> value == "*" || claim == value
            is Collection<*> -> value == "*" || value in claim
            else -> false
        }
}