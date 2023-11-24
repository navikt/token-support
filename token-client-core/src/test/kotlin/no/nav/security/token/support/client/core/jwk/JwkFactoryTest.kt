package no.nav.security.token.support.client.core.jwk

import com.nimbusds.jose.util.Base64URL
import java.io.IOException
import java.io.InputStream
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.cert.CertificateException
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test
import org.slf4j.LoggerFactory
import no.nav.security.token.support.client.core.jwk.JwkFactory.fromJsonFile
import no.nav.security.token.support.client.core.jwk.JwkFactory.fromKeyStore

internal class JwkFactoryTest {

    @Test
    fun keyFromJwkFile() {
            val rsaKey = fromJsonFile("src/test/resources/jwk.json")
            Assertions.assertThat(rsaKey.keyID).isEqualTo("jlAX4HYKW4hyhZgSmUyOmVAqMUw")
            Assertions.assertThat(rsaKey.isPrivate).isTrue()
            Assertions
                .assertThat(rsaKey.privateExponent)
                .hasToString("J_mMSpq8k4WH9GKeS6d1kPVrQz2jDslAy3b3zrBuiSdNtKgUN7jFhGXaiY-cAg3efhMc-MWwPa0raKEN9xQRtIdbJurJbNG3viCvo_8FNs5lmFCUIktuO12zvsJS63q-i1zsZ7_esYQHbeDqg9S3q98c2EIO8lxQvPBcq-OIjdxfuanAEWJIRNuvNkK5I0AcqF_Q_KeFQDHo5sWUkwyPCaddd-ogS_YDeK3eeUpQbElrusdv0Ai0iYBPukzEHz1aL8PbaYru9f6Alor6yt9Lc_FNKfi-gnNFdpg3-uqVEh-MhEXgyN1RkeZzt0Kk9rylHumjSpwEgzuuA2L3WnycUQ")
        }

    @Test
    fun keyFromKeystore()  {
            val rsaKey = fromKeyStore(
                ALIAS,
                JwkFactoryTest::class.java.getResourceAsStream(KEY_STORE_FILE),
                "Test1234"
                                     )
            Assertions.assertThat(rsaKey.keyID).isEqualTo(certificateThumbprintSHA1())
            Assertions.assertThat(rsaKey.isPrivate).isTrue()
        }

    companion object {

        private const val KEY_STORE_FILE = "/selfsigned.jks"
        private const val ALIAS = "client_assertion"
        private val log = LoggerFactory.getLogger(JwkFactoryTest::class.java)
        private fun certificateThumbprintSHA1() : String {
            return try {
                val keyStore = KeyStore.getInstance("JKS")
                keyStore.load(inputStream(KEY_STORE_FILE), "Test1234".toCharArray())
                val cert = keyStore.getCertificate(ALIAS)
                val sha1 = MessageDigest.getInstance("SHA-1")
                Base64URL.encode(sha1.digest(cert.encoded)).toString()
            }
            catch (e : KeyStoreException) {
                throw RuntimeException(e)
            }
            catch (e : IOException) {
                throw RuntimeException(e)
            }
            catch (e : CertificateException) {
                throw RuntimeException(e)
            }
            catch (e : NoSuchAlgorithmException) {
                throw RuntimeException(e)
            }
        }

        private fun inputStream(resource : String) : InputStream {
            return JwkFactoryTest::class.java.getResourceAsStream(resource)
        }
    }
}