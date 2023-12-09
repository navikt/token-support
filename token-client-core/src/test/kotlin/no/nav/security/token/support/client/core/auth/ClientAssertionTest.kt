package no.nav.security.token.support.client.core.auth

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.GrantType.*
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.*
import com.nimbusds.oauth2.sdk.auth.JWTAuthentication
import java.net.URI
import java.text.ParseException
import java.time.Instant
import java.util.Date
import java.util.Objects
import org.assertj.core.api.Assertions.*
import org.junit.jupiter.api.Test
import no.nav.security.token.support.client.core.ClientAuthenticationProperties.Companion.builder
import no.nav.security.token.support.client.core.ClientProperties.Companion.builder

internal class ClientAssertionTest {

    @Test
    @Throws(ParseException::class, JOSEException::class)
    fun testCreateAssertion() {
        val clientAuth = builder("client1", PRIVATE_KEY_JWT)
            .clientJwk("src/test/resources/jwk.json")
            .build()
        val clientProperties = builder(CLIENT_CREDENTIALS, clientAuth)
            .tokenEndpointUrl(URI.create("http://token"))
            .build()
        val now = Instant.now()
        val clientAssertion = ClientAssertion(
            clientProperties.tokenEndpointUrl,
            clientProperties.authentication)
        assertThat(clientAssertion).isNotNull()
        val assertion = clientAssertion.assertion()
        assertThat(clientAssertion.assertion()).isNotNull()
        val signedJWT = SignedJWT.parse(assertion)
        val keyId = Objects.requireNonNull(clientProperties.authentication.clientRsaKey)?.keyID
        assertThat(signedJWT.header.keyID).isEqualTo(keyId)
        assertThat(signedJWT.header.type).isEqualTo(JOSEObjectType.JWT)
        assertThat(signedJWT.header.algorithm).isEqualTo(JWSAlgorithm.RS256)
        val verifier : JWSVerifier = RSASSAVerifier(Objects.requireNonNull(clientAuth.clientRsaKey))
        assertThat(signedJWT.verify(verifier)).isTrue()
        val claims = signedJWT.jwtClaimsSet
        assertThat(claims.subject).isEqualTo(clientAuth.clientId)
        assertThat(claims.issuer).isEqualTo(clientAuth.clientId)
        assertThat(claims.audience).containsExactly(clientProperties.tokenEndpointUrl.toString())
        assertThat(claims.expirationTime).isAfter(Date.from(now))
        assertThat(claims.notBeforeTime).isBefore(claims.expirationTime)
    }
}