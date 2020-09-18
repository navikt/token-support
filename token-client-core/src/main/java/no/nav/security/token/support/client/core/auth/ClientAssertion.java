package no.nav.security.token.support.client.core.auth;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import no.nav.security.token.support.client.core.ClientAuthenticationProperties;

import javax.validation.constraints.NotNull;
import java.net.URI;
import java.sql.Date;
import java.time.Instant;
import java.util.UUID;

public class ClientAssertion {

    private static final int EXPIRY_IN_SECONDS = 60;
    private final URI tokenEndpointUrl;
    private final String clientId;
    private final RSAKey rsaKey;
    private final int expiryInSeconds;

    public ClientAssertion(@NotNull URI tokenEndpointUrl,
                           @NotNull ClientAuthenticationProperties clientAuthenticationProperties) {
        this(
            tokenEndpointUrl,
            clientAuthenticationProperties.getClientId(),
            clientAuthenticationProperties.getClientRsaKey(),
            EXPIRY_IN_SECONDS
        );
    }

    public ClientAssertion(URI tokenEndpointUrl, String clientId, RSAKey rsaKey, int expiryInSeconds) {
        this.tokenEndpointUrl = tokenEndpointUrl;
        this.rsaKey = rsaKey;
        this.clientId = clientId;
        this.expiryInSeconds = expiryInSeconds;
    }

    public String assertion() {
        Instant now = Instant.now();
        return createSignedJWT(rsaKey, new JWTClaimsSet.Builder()
            .audience(tokenEndpointUrl.toString())
            .expirationTime(Date.from(now.plusSeconds(expiryInSeconds)))
            .issuer(clientId)
            .subject(clientId)
            .claim("jti", UUID.randomUUID().toString())
            .notBeforeTime(Date.from(now))
            .issueTime(Date.from(now))
            .build()).serialize();
    }

    public String assertionType() {
        return "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    }

    private SignedJWT createSignedJWT(RSAKey rsaJwk, JWTClaimsSet claimsSet) {
        try {
            JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(rsaJwk.getKeyID())
                .type(JOSEObjectType.JWT);
            SignedJWT signedJWT = new SignedJWT(header.build(), claimsSet);
            JWSSigner signer = new RSASSASigner(rsaJwk.toPrivateKey());
            signedJWT.sign(signer);
            return signedJWT;
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }
}
