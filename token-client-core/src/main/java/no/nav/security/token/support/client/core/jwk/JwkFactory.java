package no.nav.security.token.support.client.core.jwk;


import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Optional;
import java.util.function.Supplier;

public class JwkFactory {

    private static final boolean USE_CERTIFICATE_SHA1_THUMBPRINT = true;

    public static RSAKey fromJsonFile(String filePath){
        try {

            String jsonJwk = Files.readString(Path.of(filePath), StandardCharsets.UTF_8);
            return fromJson(jsonJwk);
        } catch (IOException e) {
            throw new JwkInvalidException(e);
        }
    }

    public static RSAKey fromJson(String jsonJwk){
        try {
            return RSAKey.parse(jsonJwk);
        } catch (ParseException e) {
            throw new JwkInvalidException(e);
        }
    }

    public static RSAKey fromKeyStore(String alias, InputStream keyStoreFile, String password) {
        RSAKey keyFromKeyStore = (RSAKey) fromKeyStore(keyStoreFile, password).getKeyByKeyId(alias);
        return new RSAKey.Builder(keyFromKeyStore)
                .keyID(USE_CERTIFICATE_SHA1_THUMBPRINT ?
                        getX509CertSHA1Thumbprint(keyFromKeyStore)
                        : keyFromKeyStore.getKeyID())
                .build();

    }

    private static JWKSet fromKeyStore(InputStream keyStoreFile, String password) {
        try {
            char[] pwd = Optional.ofNullable(password)
                    .map(String::toCharArray)
                    .orElseThrow(jwkInvalid("password cannot be null"));
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(keyStoreFile, pwd);
            return JWKSet.load(keyStore, name -> pwd);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    private static String getX509CertSHA1Thumbprint(RSAKey rsaKey) {
        X509Certificate cert = rsaKey.getParsedX509CertChain().stream()
                .findFirst()
                .orElse(null);
        try {
            return cert != null ? createSHA1DigestBase64Url(cert.getEncoded()) : null;
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    private static String createSHA1DigestBase64Url(byte[] bytes) {
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            return Base64URL.encode(sha1.digest(bytes)).toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static Supplier<JwkInvalidException> jwkInvalid(String msg) {
        return () -> new JwkInvalidException(msg);
    }

    public static class JwkInvalidException extends RuntimeException {
        JwkInvalidException(String message) {
            super(message);
        }

        JwkInvalidException(Throwable cause) {
            super(cause);
        }
    }
}


