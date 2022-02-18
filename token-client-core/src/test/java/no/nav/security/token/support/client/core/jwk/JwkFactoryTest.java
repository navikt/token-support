package no.nav.security.token.support.client.core.jwk;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import static org.assertj.core.api.Assertions.assertThat;

class JwkFactoryTest {

    private static final String KEY_STORE_FILE = "/selfsigned.jks";
    private static final String ALIAS = "client_assertion";
    private static final Logger log = LoggerFactory.getLogger(JwkFactoryTest.class);

    @Test
    void getKeyFromJwkFile() {
        RSAKey rsaKey = JwkFactory.fromJsonFile("src/test/resources/jwk.json");
        assertThat(rsaKey.getKeyID()).isEqualTo("jlAX4HYKW4hyhZgSmUyOmVAqMUw");
        assertThat(rsaKey.isPrivate()).isTrue();
        assertThat(rsaKey.getPrivateExponent().toString()).isEqualTo("J_mMSpq8k4WH9GKeS6d1kPVrQz2jDslAy3b3zrBuiSdNtKgUN7jFhGXaiY-cAg3efhMc-MWwPa0raKEN9xQRtIdbJurJbNG3viCvo_8FNs5lmFCUIktuO12zvsJS63q-i1zsZ7_esYQHbeDqg9S3q98c2EIO8lxQvPBcq-OIjdxfuanAEWJIRNuvNkK5I0AcqF_Q_KeFQDHo5sWUkwyPCaddd-ogS_YDeK3eeUpQbElrusdv0Ai0iYBPukzEHz1aL8PbaYru9f6Alor6yt9Lc_FNKfi-gnNFdpg3-uqVEh-MhEXgyN1RkeZzt0Kk9rylHumjSpwEgzuuA2L3WnycUQ");
    }

    @Test
    void getKeyFromKeystore() {
        RSAKey rsaKey = JwkFactory.fromKeyStore(
            ALIAS,
            JwkFactoryTest.class.getResourceAsStream(KEY_STORE_FILE),
            "Test1234"
        );
        assertThat(rsaKey.getKeyID()).isEqualTo(certificateThumbprintSHA1());
        assertThat(rsaKey.isPrivate()).isTrue();
    }

    private static String certificateThumbprintSHA1() {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(inputStream(KEY_STORE_FILE), "Test1234".toCharArray());
            Certificate cert = keyStore.getCertificate(ALIAS);
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            return Base64URL.encode(sha1.digest(cert.getEncoded())).toString();
        } catch (KeyStoreException | IOException | CertificateException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static InputStream inputStream(String resource) {
        return JwkFactoryTest.class.getResourceAsStream(resource);
    }

}
