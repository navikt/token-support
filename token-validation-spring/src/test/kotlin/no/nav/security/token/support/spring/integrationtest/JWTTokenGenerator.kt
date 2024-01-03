package no.nav.security.token.support.spring.integrationtest

import com.nimbusds.jose.JOSEObjectType.*
import com.nimbusds.jose.JWSAlgorithm.*
import com.nimbusds.jose.JWSHeader.Builder
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT

object JwtTokenGenerator {
    const val AUD = "aud-localhost"
    const val ACR = "Level4"

    fun createSignedJWT(rsaJwk: RSAKey, claimsSet: JWTClaimsSet?) =
        SignedJWT(Builder(RS256)
            .keyID(rsaJwk.keyID)
            .type(JWT).build(), claimsSet).apply {
            sign(RSASSASigner(rsaJwk.toPrivateKey()))
        }
}