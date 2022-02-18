package no.nav.security.token.support.test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.IOUtils;

@Deprecated
public class JwkGenerator {
    public static final String DEFAULT_KEYID = "localhost-signer";
    public static final String DEFAULT_JWKSET_FILE = "/jwkset.json";

    public JwkGenerator() {
    }

    public static RSAKey getDefaultRSAKey() {
        return (RSAKey) getJWKSet().getKeyByKeyId(DEFAULT_KEYID);
    }

    public static RSAKey getRSAKey(String keyID) {
        return (RSAKey) getJWKSet().getKeyByKeyId(keyID);
    }

    public static JWKSet getJWKSet() {
        try {
            return JWKSet.parse(IOUtils.readInputStreamToString(
                    JwkGenerator.class.getResourceAsStream(DEFAULT_JWKSET_FILE), StandardCharsets.UTF_8));
        } catch (IOException | ParseException io) {
            throw new RuntimeException(io);
        }
    }

    public static JWKSet getJWKSetFromFile(File file) {
        try {
            return JWKSet.load(file);
        } catch (IOException | ParseException e) {
            throw new RuntimeException(e);
        }
    }

    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            return gen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static RSAKey createJWK(String keyID, KeyPair keyPair) {
        return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyID(keyID)
                .build();
    }
}
