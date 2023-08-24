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
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

abstract class AbstractJwtValidatorTest {

    protected static final String DEFAULT_ISSUER = "https://issuer";
    protected static final String DEFAULT_SUBJECT = "foobar";
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

    protected String token(String audience) {
        return token(Collections.singletonList(audience));
    }

    protected String token(List<String> audience) {
        return token(defaultClaims().audience(audience).build());
    }

    protected String token(JWTClaimsSet claims) {
        return createSignedJWT(claims).serialize();
    }

    protected SignedJWT createSignedJWT(String issuer, String audience, String sub) {
        return createSignedJWT(defaultClaims()
            .issuer(issuer)
            .audience(audience)
            .subject(sub)
            .build()
        );
    }

    protected JWTClaimsSet.Builder defaultClaims() {
        var now = new Date();
        var expiry = new Date(now.getTime() + TimeUnit.HOURS.toMillis(1));
        return new JWTClaimsSet.Builder()
            .issuer(DEFAULT_ISSUER)
            .subject(DEFAULT_SUBJECT)
            .jwtID(UUID.randomUUID().toString())
            .notBeforeTime(now)
            .issueTime(now)
            .expirationTime(expiry);
    }

    private SignedJWT createSignedJWT(JWTClaimsSet claimsSet) {
        try {
            var header = new JWSHeader.Builder(JWSAlgorithm.RS256)
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

    class MockResourceRetriever extends ProxyAwareResourceRetriever {
        @Override
        public Resource retrieveResource(URL url) throws IOException {
            JWKSet set = new JWKSet(rsaJwk);
            String content = set.toString();
            return new Resource(content, "application/json");
        }
    }
}
