package no.nav.security.token.support.core.validation;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import no.nav.security.token.support.core.configuration.ProxyAwareResourceRetriever;

import java.io.IOException;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.List;
import java.util.UUID;

abstract class AbstractJwtValidatorTest {

    private static final String KEYID = "myKeyId";
    private final RSAKey rsaJwk = setupKeys(KEYID);

    protected RSAKey setupKeys(String keyId) {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048); // just for testing so 1024 is ok
            KeyPair keyPair = gen.generateKeyPair();
            return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyID(keyId).build();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    protected SignedJWT createSignedJWT(String issuer, List<String> claims, String audience, String sub) {
        try {
            JWTClaimsSet claimsSet = setClaims(issuer, claims, audience, sub);
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

    private JWTClaimsSet setClaims(String issuer, List<String> claims, String audience, String sub) {
        Date now = new Date();
        return sub != null ? new JWTClaimsSet.Builder()
            .subject(sub)
            .issuer(issuer)
            .audience(audience)
            .jwtID(UUID.randomUUID().toString()).notBeforeTime(now).issueTime(now)
            .expirationTime(new Date(now.getTime() + 3600)).build()
            : new JWTClaimsSet.Builder()
            .issuer(issuer)
            .claim(claims.get(0), "somevalue")
            .audience(audience)
            .jwtID(UUID.randomUUID().toString()).notBeforeTime(now).issueTime(now)
            .expirationTime(new Date(now.getTime() + 3600)).build();
    }

    class MockResourceRetriever extends ProxyAwareResourceRetriever {
        @Override
        public Resource retrieveResource(URL url) throws IOException {
            JWKSet set = new JWKSet(rsaJwk);
            String content = set.toString();
            return new Resource(content, "application/json");
        }
    }
}
