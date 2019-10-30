package no.nav.security.token.support.client.core.auth;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import no.nav.security.token.support.client.core.ClientAuthenticationProperties;
import no.nav.security.token.support.client.core.ClientProperties;
import no.nav.security.token.support.client.core.OAuth2GrantType;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

class ClientAssertionTest {

    @Test
    void testCreateAssertion() throws ParseException, JOSEException {
        ClientAuthenticationProperties clientAuth = ClientAuthenticationProperties.builder()
            .clientPrivateKey("src/test/resources/jwk.json")
            .clientId("client1")
            .clientAuthMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
            .build();

        ClientProperties clientProperties = ClientProperties.builder()
            .grantType(OAuth2GrantType.CLIENT_CREDENTIALS)
            .tokenEndpointUrl(URI.create("http://token"))
            .authentication(clientAuth)
            .build();

        Instant now = Instant.now();

        ClientAssertion clientAssertion = new ClientAssertion(
            clientProperties.getTokenEndpointUrl(),
            clientProperties.getAuthentication());

        assertThat(clientAssertion).isNotNull();
        assertThat(clientAssertion.assertionType()).isEqualTo("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");

        String assertion = clientAssertion.assertion();
        assertThat(clientAssertion.assertion()).isNotNull();

        SignedJWT signedJWT = SignedJWT.parse(assertion);
        String keyId = clientProperties.getAuthentication().getClientRsaKey().getKeyID();
        assertThat(signedJWT.getHeader().getKeyID()).isEqualTo(keyId);
        assertThat(signedJWT.getHeader().getType()).isEqualTo(JOSEObjectType.JWT);
        assertThat(signedJWT.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);

        JWSVerifier verifier = new RSASSAVerifier(clientAuth.getClientRsaKey());
        assertThat(signedJWT.verify(verifier)).isTrue();

        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
        assertThat(claims.getSubject()).isEqualTo(clientAuth.getClientId());
        assertThat(claims.getIssuer()).isEqualTo(clientAuth.getClientId());
        assertThat(claims.getAudience()).containsExactly(clientProperties.getTokenEndpointUrl().toString());
        assertThat(claims.getExpirationTime()).isAfter(Date.from(now));
        assertThat(claims.getNotBeforeTime()).isBefore(claims.getExpirationTime());
    }
}
