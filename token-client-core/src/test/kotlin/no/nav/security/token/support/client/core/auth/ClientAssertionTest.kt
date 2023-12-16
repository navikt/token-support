package no.nav.security.token.support.client.core.auth

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.GrantType.CLIENT_CREDENTIALS
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.PRIVATE_KEY_JWT
import java.net.URI
import java.text.ParseException
import java.time.Instant
import java.util.Date
import java.util.Objects
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import no.nav.security.token.support.client.core.ClientAuthenticationProperties.Companion.builder
import no.nav.security.token.support.client.core.ClientProperties.Companion.builder

internal class ClientAssertionTest {

    @Test
    @Throws(ParseException::class, JOSEException::class)
    fun testCreateAssertion() {
        val clientAuth = builder("client1", PRIVATE_KEY_JWT).clientJwk("src/test/resources/jwk.json").build()
        val p = builder(CLIENT_CREDENTIALS, clientAuth).tokenEndpointUrl(URI.create("http://token")).build()

        val signedJWT = SignedJWT.parse(ClientAssertion(p.tokenEndpointUrl, p.authentication).assertion())
        val keyId = Objects.requireNonNull(p.authentication.clientRsaKey)?.keyID
        assertThat(signedJWT.header.keyID).isEqualTo(keyId)
        assertThat(signedJWT.header.type).isEqualTo(JOSEObjectType.JWT)
        assertThat(signedJWT.header.algorithm).isEqualTo(JWSAlgorithm.RS256)
        val verifier = RSASSAVerifier(Objects.requireNonNull(clientAuth.clientRsaKey))
        assertThat(signedJWT.verify(verifier)).isTrue()

        val claims = signedJWT.jwtClaimsSet
        assertThat(claims.subject).isEqualTo(clientAuth.clientId)
        assertThat(claims.issuer).isEqualTo(clientAuth.clientId)
        assertThat(claims.audience).containsExactly(p.tokenEndpointUrl.toString())
        assertThat(claims.expirationTime).isAfter(Date.from(Instant.now()))
        assertThat(claims.notBeforeTime).isBefore(claims.expirationTime)
    }
}