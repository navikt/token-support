package no.nav.security.token.support.core.jwt

import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.SignedJWT
import kotlin.DeprecationLevel.WARNING

open class JwtToken(val encodedToken : String, protected val jwt : JWT, val jwtTokenClaims : JwtTokenClaims) {
    constructor(encodedToken : String) : this(encodedToken, JWTParser.parse(encodedToken), JwtTokenClaims(JWTParser.parse(encodedToken).jwtClaimsSet))

    val jwtClaimsSet = jwt.jwtClaimsSet

    val subject  = jwtTokenClaims.subject

    val issuer = jwtTokenClaims.issuer

    @Deprecated("Use getEncodedToken instead", ReplaceWith("getEncodedToken()"), WARNING)
    val tokenAsString = encodedToken

    fun asBearer() = "Bearer $encodedToken"

    fun containsClaim(name : String, value : String)  = jwtTokenClaims.containsClaim(name, value)

    companion object {
         fun SignedJWT.asBearer() = "Bearer ${serialize()}"
    }
}