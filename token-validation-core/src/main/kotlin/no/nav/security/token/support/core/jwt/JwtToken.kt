package no.nav.security.token.support.core.jwt

import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTParser

open class JwtToken(private val encodedToken : String, protected val jwt : JWT, val jwtTokenClaims : JwtTokenClaims) {
    constructor(encodedToken : String) : this(encodedToken, JWTParser.parse(encodedToken), JwtTokenClaims(JWTParser.parse(encodedToken).jwtClaimsSet))

    fun getJwtClaimsSet() = jwt.jwtClaimsSet

    fun getSubject()  = jwtTokenClaims.subject

    fun getIssuer() = jwtTokenClaims.issuer

    fun getTokenAsString() = encodedToken

    fun containsClaim(name : String, value : String)  = jwtTokenClaims.containsClaim(name, value)

}