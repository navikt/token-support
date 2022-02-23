package no.nav.security.token.support.jaxrs;

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

import static java.nio.charset.StandardCharsets.*;

 class JwkGenerator {
     private static final String DEFAULT_KEYID = "localhost-signer";
     static final String DEFAULT_JWKSET_FILE = "/jwkset.json";

    private JwkGenerator() {
    }

     static RSAKey getDefaultRSAKey() {
        return (RSAKey) getJWKSet().getKeyByKeyId(DEFAULT_KEYID);
    }

     public static JWKSet getJWKSet() {
        try {
            return JWKSet.parse(IOUtils.readInputStreamToString(
                JwkGenerator.class.getResourceAsStream(DEFAULT_JWKSET_FILE), UTF_8));
        } catch (IOException | ParseException io) {
            throw new RuntimeException(io);
        }
    }

}
