package no.nav.security.token.support.client.core.jwk;


import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.Optional;

import static java.nio.charset.StandardCharsets.UTF_8;

public class JwkFactory {

    private static final Logger LOG = LoggerFactory.getLogger(JwkFactory.class);
    private static final boolean USE_CERTIFICATE_SHA1_THUMBPRINT = true;

    public static RSAKey fromJsonFile(String filePath){
        try {
            LOG.debug("attempting to read jwk from path: {}", Path.of(filePath).toAbsolutePath());
            return fromJson(Files.readString(Path.of(filePath), UTF_8));
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
        var keyFromKeyStore = (RSAKey) fromKeyStore(keyStoreFile, password).getKeyByKeyId(alias);
        return new RSAKey.Builder(keyFromKeyStore)
                .keyID(USE_CERTIFICATE_SHA1_THUMBPRINT ?
                        getX509CertSHA1Thumbprint(keyFromKeyStore)
                        : keyFromKeyStore.getKeyID())
                .build();
    }

    private static JWKSet fromKeyStore(InputStream keyStoreFile, String password) {
        try {
            var pwd = Optional.ofNullable(password)
                    .map(String::toCharArray)
                    .orElseThrow(() -> new JwkInvalidException("password cannot be null"));
            var keyStore = KeyStore.getInstance("JKS");
            keyStore.load(keyStoreFile, pwd);
            return JWKSet.load(keyStore, name -> pwd);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    private static String getX509CertSHA1Thumbprint(RSAKey rsaKey) {
        var cert = rsaKey.getParsedX509CertChain().stream()
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
            return Base64URL.encode(MessageDigest.getInstance("SHA-1").digest(bytes)).toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
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
