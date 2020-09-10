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
import java.util.*

class ClientAssertion(
    private val clientConfig: ClientProperties
) {

    companion object {
        const val SCOPE = "scope"
    }

    // Generate a client assertion
    fun assertion(): String {
        val now = Date.from(Instant.now())
        return JWTClaimsSet.Builder()
            .issuer(clientConfig.authentication.clientId)
            .audience(clientConfig.tokenEndpointUrl.toString())
            .issueTime(now)
            .expirationTime(Date.from(Instant.now().plusSeconds(120)))
            .jwtID(UUID.randomUUID().toString())
            // Scope(s) required as a single string - space separated
            .claim(SCOPE, clientConfig.scope.joinToString(" "))
            .build()
            .sign(clientConfig.authentication.clientRsaKey)
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