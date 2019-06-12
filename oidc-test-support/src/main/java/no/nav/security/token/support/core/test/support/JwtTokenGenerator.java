package no.nav.security.token.support.core.test.support;

import java.util.Date;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSHeader.Builder;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class JwtTokenGenerator {

    public static final String ISS = "iss-localhost";
    public static final String AUD = "aud-localhost";
    public static final String ACR = "Level4";
    public static final long EXPIRY = 60 * 60 * 3600;

    private JwtTokenGenerator() {
    }

    public static String signedJWTAsString(String subject) {
        return createSignedJWT(subject).serialize();
    }

    public static SignedJWT createSignedJWT(String subject) {
        return createSignedJWT(subject, EXPIRY);
    }

    public static SignedJWT createSignedJWT(String subject, long expiryInMinutes) {
        JWTClaimsSet claimsSet = buildClaimSet(subject, ISS, AUD, ACR, TimeUnit.MINUTES.toMillis(expiryInMinutes));
        return createSignedJWT(JwkGenerator.getDefaultRSAKey(), claimsSet);
    }

    public static SignedJWT createSignedJWT(JWTClaimsSet claimsSet) {
        return createSignedJWT(JwkGenerator.getDefaultRSAKey(), claimsSet);
    }

    public static JWTClaimsSet buildClaimSet(String subject, String issuer, String audience, String authLevel,
            long expiry) {
        Date now = new Date();
        return new JWTClaimsSet.Builder()
                .subject(subject)
                .issuer(issuer)
                .audience(audience)
                .jwtID(UUID.randomUUID().toString())
                .claim("acr", authLevel)
                .claim("ver", "1.0")
                .claim("nonce", "myNonce")
                .claim("auth_time", now)
                .notBeforeTime(now)
                .issueTime(now)
                .expirationTime(new Date(now.getTime() + expiry)).build();
    }

    public static SignedJWT createSignedJWT(RSAKey rsaJwk, JWTClaimsSet claimsSet) {
        try {
            JWSHeader.Builder header = new Builder(JWSAlgorithm.RS256)
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
