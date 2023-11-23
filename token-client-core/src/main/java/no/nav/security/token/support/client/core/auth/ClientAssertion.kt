package no.nav.security.token.support.client.core.auth

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JOSEObjectType.*
import com.nimbusds.jose.JWSAlgorithm.*
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTClaimsSet.Builder
import com.nimbusds.jwt.SignedJWT
import java.net.URI
import java.time.Instant
import java.time.Instant.*
import java.util.Date
import java.util.UUID
import no.nav.security.token.support.client.core.ClientAuthenticationProperties

class ClientAssertion(private val tokenEndpointUrl : URI, private val clientId : String, private val rsaKey : RSAKey, private val expiryInSeconds : Int) {
    constructor(tokenEndpointUrl: URI, auth :  ClientAuthenticationProperties) : this(tokenEndpointUrl, auth.clientId, auth.clientRsaKey, EXPIRY_IN_SECONDS)

    fun assertion()  =
        now().run {
            createSignedJWT(rsaKey, Builder()
                .audience(tokenEndpointUrl.toString())
                .expirationTime(Date.from(plusSeconds(expiryInSeconds.toLong())))
                .issuer(clientId)
                .subject(clientId)
                .claim("jti", UUID.randomUUID().toString())
                .notBeforeTime(Date.from(this))
                .issueTime(Date.from(this))
                .build()).serialize()
        }

    fun assertionType() = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

    private fun createSignedJWT(rsaJwk : RSAKey, claimsSet : JWTClaimsSet) =

        runCatching {
            SignedJWT(JWSHeader.Builder(RS256)
                .keyID(rsaJwk.keyID)
                .type(JWT).build(), claimsSet).apply {
                    sign(RSASSASigner(rsaJwk.toPrivateKey()))
                }
        }.getOrElse {
            throw RuntimeException(it)
        }

    companion object {
        private const val EXPIRY_IN_SECONDS = 60
    }
}