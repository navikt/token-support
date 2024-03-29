package no.nav.security.token.support.client.core.jwk

import com.nimbusds.jose.util.Base64URL.encode
import java.security.KeyStore
import java.security.MessageDigest.getInstance
import no.nav.security.token.support.client.core.jwk.JwkFactory.fromJsonFile
import no.nav.security.token.support.client.core.jwk.JwkFactory.fromKeyStore
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

internal class JwkFactoryTest {

    @Test
    fun keyFromJwkFile() {
            val rsaKey = fromJsonFile("src/test/resources/jwk.json")
            assertThat(rsaKey.keyID).isEqualTo("jlAX4HYKW4hyhZgSmUyOmVAqMUw")
            assertThat(rsaKey.isPrivate).isTrue()
            assertThat(rsaKey.privateExponent).hasToString("J_mMSpq8k4WH9GKeS6d1kPVrQz2jDslAy3b3zrBuiSdNtKgUN7jFhGXaiY-cAg3efhMc-MWwPa0raKEN9xQRtIdbJurJbNG3viCvo_8FNs5lmFCUIktuO12zvsJS63q-i1zsZ7_esYQHbeDqg9S3q98c2EIO8lxQvPBcq-OIjdxfuanAEWJIRNuvNkK5I0AcqF_Q_KeFQDHo5sWUkwyPCaddd-ogS_YDeK3eeUpQbElrusdv0Ai0iYBPukzEHz1aL8PbaYru9f6Alor6yt9Lc_FNKfi-gnNFdpg3-uqVEh-MhEXgyN1RkeZzt0Kk9rylHumjSpwEgzuuA2L3WnycUQ")
        }

    @Test
    fun keyFromKeystore()  {
            val rsaKey = fromKeyStore(ALIAS, inputStream(KEY_STORE_FILE), "Test1234")
            assertThat(rsaKey.keyID).isEqualTo(certificateThumbprintSHA1())
            assertThat(rsaKey.isPrivate).isTrue()
        }

    companion object {

        private const val KEY_STORE_FILE = "/selfsigned.jks"
        private const val ALIAS = "client_assertion"
        private fun certificateThumbprintSHA1() : String {
            return try {
                val keyStore = KeyStore.getInstance("JKS").apply {
                    load(inputStream(KEY_STORE_FILE), "Test1234".toCharArray())
                }
                "${encode(getInstance("SHA-1").digest(keyStore.getCertificate(ALIAS).encoded))}"
            }
            catch (e : Exception) {
                throw RuntimeException(e)
            }
        }

        private fun inputStream(resource : String) = JwkFactoryTest::class.java.getResourceAsStream(resource) ?: throw IllegalArgumentException("resource not found: $resource")

    }
}