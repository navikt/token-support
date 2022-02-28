package no.nav.security.token.support.jaxrs;

import java.util.Date;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader.Builder;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

 class JwtTokenGenerator {

     static final String ISS = "iss-localhost";
     static final String AUD = "aud-localhost";
     static final String ACR = "Level4";
     static final long EXPIRY = 60 * 60 * 3600;

    private JwtTokenGenerator() {
    }

      static SignedJWT createSignedJWT(String subject) {
        return createSignedJWT(subject, EXPIRY);
    }

     static SignedJWT createSignedJWT(String subject, long expiryInMinutes) {
        var claimsSet = buildClaimSet(subject, ISS, AUD, ACR, TimeUnit.MINUTES.toMillis(expiryInMinutes));
        return createSignedJWT(JwkGenerator.getDefaultRSAKey(), claimsSet);
    }

      static JWTClaimsSet buildClaimSet(String subject, String issuer, String audience, String authLevel,
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

     static SignedJWT createSignedJWT(RSAKey rsaJwk, JWTClaimsSet claimsSet) {
        try {
            var header = new Builder(JWSAlgorithm.RS256)
                .keyID(rsaJwk.getKeyID())
                .type(JOSEObjectType.JWT);

            var signedJWT = new SignedJWT(header.build(), claimsSet);
            var signer = new RSASSASigner(rsaJwk.toPrivateKey());
            signedJWT.sign(signer);

            return signedJWT;
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }
}
