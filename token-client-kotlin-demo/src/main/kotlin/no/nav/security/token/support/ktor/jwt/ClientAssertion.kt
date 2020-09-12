package no.nav.security.token.support.ktor.jwt

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import no.nav.security.token.support.client.core.ClientProperties
import java.time.Instant
import java.util.Date
import java.util.UUID

class ClientAssertion(
    private val config: ClientProperties
) {

    companion object {
        const val SCOPE = "scope"
    }

    // Generate a client assertion
    fun assertion(): String {
        val now = Date.from(Instant.now())
        return JWTClaimsSet.Builder()
            .issuer(config.authentication.clientId)
            .audience(config.tokenEndpointUrl.toString())
            .issueTime(now)
            .expirationTime(Date.from(Instant.now().plusSeconds(120)))
            .jwtID(UUID.randomUUID().toString())
            // Scope(s) required as a single string - space separated
            .claim(SCOPE, config.scope.joinToString(" "))
            .build()
            .sign(config.authentication.clientRsaKey)
            .serialize()
    }

    private fun JWTClaimsSet.sign(rsaKey: RSAKey): SignedJWT =
        SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(rsaKey.keyID)
                .type(JOSEObjectType.JWT).build(),
            this
        ).apply {
            sign(RSASSASigner(rsaKey.toPrivateKey()))
        }
}