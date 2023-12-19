package no.nav.security.token.support.jaxrs

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JOSEObjectType.*
import com.nimbusds.jose.JWSAlgorithm.*
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTClaimsSet.Builder
import com.nimbusds.jwt.SignedJWT
import java.util.Date
import java.util.UUID
import java.util.concurrent.TimeUnit.MINUTES
import no.nav.security.token.support.jaxrs.JwkGenerator.defaultRSAKey

internal object JwtTokenGenerator {

    const val ISS : String = "iss-localhost"
    const val AUD : String = "aud-localhost"
    const val ACR : String = "Level4"
    const val EXPIRY : Long = (60 * 60 * 3600).toLong()

    fun createSignedJWT(subject : String?, expiryInMinutes : Long = EXPIRY) =
        createSignedJWT(defaultRSAKey, buildClaimSet(subject, ISS, AUD, ACR, MINUTES.toMillis(expiryInMinutes)))

    fun buildClaimSet(subject : String?, issuer : String?, audience : String?, authLevel : String?, expiry : Long) : JWTClaimsSet =
        Date().run {
            Builder()
                .subject(subject)
                .issuer(issuer)
                .audience(audience)
                .jwtID(UUID.randomUUID().toString())
                .claim("acr", authLevel)
                .claim("ver", "1.0")
                .claim("nonce", "myNonce")
                .claim("auth_time", this)
                .notBeforeTime(this)
                .issueTime(this)
                .expirationTime(Date(time + expiry)).build()
        }

    fun createSignedJWT(rsaJwk : RSAKey, claimsSet : JWTClaimsSet?) =
        SignedJWT(JWSHeader.Builder(RS256)
            .keyID(rsaJwk.keyID)
            .type(JWT).build(), claimsSet).apply {
            sign(RSASSASigner(rsaJwk.toPrivateKey()))
        }
}