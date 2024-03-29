package no.nav.security.token.support.client.core.auth

import com.nimbusds.jose.JOSEObjectType.JWT
import com.nimbusds.jose.JWSAlgorithm.RS256
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimNames.JWT_ID
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTClaimsSet.Builder
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.auth.JWTAuthentication.CLIENT_ASSERTION_TYPE
import java.net.URI
import java.time.Instant.now
import java.util.*
import no.nav.security.token.support.client.core.ClientAuthenticationProperties
import kotlin.DeprecationLevel.WARNING

class ClientAssertion(private val tokenEndpointUrl : URI, private val clientId : String, private val rsaKey : RSAKey, private val expiryInSeconds : Int) {
    constructor(tokenEndpointUrl: URI, auth :  ClientAuthenticationProperties) : this(tokenEndpointUrl, auth.clientId, auth.clientRsaKey!!, EXPIRY_IN_SECONDS)

    fun assertion()  =
        now().run {
            createSignedJWT(rsaKey, Builder()
                .audience("$tokenEndpointUrl")
                .expirationTime(Date.from(plusSeconds(expiryInSeconds.toLong())))
                .issuer(clientId)
                .subject(clientId)
                .claim(JWT_ID, "${UUID.randomUUID()}")
                .notBeforeTime(Date.from(this))
                .issueTime(Date.from(this))
                .build()).serialize()
        }

    @Deprecated("Use com.nimbusds.oauth2.sdk.auth.JWTAuthentication instead", ReplaceWith("JWTAuthentication.CLIENT_ASSERTION_TYPE"), WARNING)
    fun assertionType() = CLIENT_ASSERTION_TYPE

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