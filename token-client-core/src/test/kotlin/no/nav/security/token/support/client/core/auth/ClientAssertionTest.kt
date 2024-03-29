package no.nav.security.token.support.client.core.auth

import com.nimbusds.jose.JOSEObjectType.JWT
import com.nimbusds.jose.JWSAlgorithm.RS256
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.GrantType.CLIENT_CREDENTIALS
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.PRIVATE_KEY_JWT
import java.net.URI
import java.time.Instant
import java.util.*
import no.nav.security.token.support.client.core.ClientAuthenticationProperties.Companion.builder
import no.nav.security.token.support.client.core.ClientProperties.Companion.builder
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

internal class ClientAssertionTest {

    @Test
    fun testCreateAssertion() {
        val clientAuth = builder("client1", PRIVATE_KEY_JWT).clientJwk("src/test/resources/jwk.json").build()
        val p = builder(CLIENT_CREDENTIALS, clientAuth).tokenEndpointUrl(URI.create("http://token")).build()
        val signedJWT = SignedJWT.parse(ClientAssertion(p.tokenEndpointUrl!!, p.authentication).assertion())
        assertThat(signedJWT.header.keyID).isEqualTo(p.authentication.clientRsaKey?.keyID)
        assertThat(signedJWT.header.type).isEqualTo(JWT)
        assertThat(signedJWT.header.algorithm).isEqualTo(RS256)
        assertThat(signedJWT.verify(RSASSAVerifier(clientAuth.clientRsaKey))).isTrue()
        val claims = signedJWT.jwtClaimsSet
        assertThat(claims.subject).isEqualTo(clientAuth.clientId)
        assertThat(claims.issuer).isEqualTo(clientAuth.clientId)
        assertThat(claims.audience).containsExactly(p.tokenEndpointUrl.toString())
        assertThat(claims.expirationTime).isAfter(Date.from(Instant.now()))
        assertThat(claims.notBeforeTime).isBefore(claims.expirationTime)
    }
}