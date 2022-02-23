package no.nav.security.token.support.ktor

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTClaimsSet.Builder
import com.nimbusds.jwt.SignedJWT
import java.util.*
import java.util.concurrent.TimeUnit.MINUTES


object JwtTokenGenerator {
    const val ISS = "iss-localhost"
    const val AUD = "aud-localhost"
    const val ACR = "Level4"
    const val EXPIRY = (60 * 60 * 3600).toLong()
    fun signedJWTAsString(subject: String?): String {
        return createSignedJWT(subject).serialize()
    }

    @JvmOverloads
    fun createSignedJWT(subject: String?, expiryInMinutes: Long = EXPIRY): SignedJWT {
        val claimsSet = buildClaimSet(subject, ISS, AUD, ACR, MINUTES.toMillis(expiryInMinutes))
        return createSignedJWT(JwkGenerator.defaultRSAKey,
                claimsSet)
    }

    fun createSignedJWT(claimsSet: JWTClaimsSet?): SignedJWT {
        return createSignedJWT(JwkGenerator.defaultRSAKey, claimsSet)
    }

    fun buildClaimSet(subject: String?, issuer: String?, audience: String?, authLevel: String?,
                      expiry: Long): JWTClaimsSet {
        val now = Date()
        return Builder()
            .subject(subject)
            .issuer(issuer)
            .audience(audience)
            .jwtID(UUID.randomUUID().toString())
            .claim("acr", authLevel)
            .claim("ver", "1.0")
            .claim("nonce", "myNonce")
            .claim("auth_time", now)
            .notBeforeTime(now)
            .issueTime(now)
            .expirationTime(Date(now.time + expiry)).build()
    }

    fun createSignedJWT(rsaJwk: RSAKey, claimsSet: JWTClaimsSet?): SignedJWT {
        return try {
            val header = JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(rsaJwk.keyID)
                .type(JOSEObjectType.JWT)
            val signedJWT = SignedJWT(header.build(), claimsSet)
            val signer: JWSSigner = RSASSASigner(rsaJwk.toPrivateKey())
            signedJWT.sign(signer)
            signedJWT
        } catch (e: JOSEException) {
            throw RuntimeException(e)
        }
    }
}