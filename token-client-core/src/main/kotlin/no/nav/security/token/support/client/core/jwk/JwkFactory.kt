package no.nav.security.token.support.client.core.jwk

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.RSAKey.Builder
import com.nimbusds.jose.util.Base64URL.*
import java.io.InputStream
import java.nio.charset.StandardCharsets.*
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyStore
import java.security.MessageDigest.*
import java.security.NoSuchAlgorithmException
import org.slf4j.LoggerFactory

object JwkFactory {

    private val LOG = LoggerFactory.getLogger(JwkFactory::class.java)
    @JvmStatic
    fun fromJsonFile(filePath : String) =
        runCatching {
            LOG.debug("Attempting to read jwk from path: {}", Path.of(filePath).toAbsolutePath())
            fromJson(Files.readString(Path.of(filePath), UTF_8))
        }.getOrElse {
            throw JwkInvalidException(it)
        }


    @JvmStatic
    fun fromJson(jsonJwk : String) =
        runCatching {
            RSAKey.parse(jsonJwk)
        }.getOrElse {
            throw JwkInvalidException(it)
        }


    @JvmStatic
    fun fromKeyStore(alias : String, keyStoreFile : InputStream, password : String) =
        with(fromKeyStore(keyStoreFile, password).getKeyByKeyId(alias) as RSAKey) {
             Builder(this)
                .keyID(getX509CertSHA1Thumbprint(this))
                .build()
        }

    private fun fromKeyStore(keyStoreFile : InputStream, password : String) =
        runCatching {
            KeyStore.getInstance("JKS").run {
                with(password.toCharArray()) {
                    load(keyStoreFile, this)
                    JWKSet.load(this@run) { this }
                }
            }
        }.getOrElse {
            throw RuntimeException(it)
        }


    private fun getX509CertSHA1Thumbprint(rsaKey : RSAKey) : String? {
        return runCatching {
            rsaKey.parsedX509CertChain.stream()
                .findFirst()
                .orElse(null)?.let { createSHA1DigestBase64Url(it.encoded) }
        }.getOrElse {
            throw RuntimeException(it)
        }
    }

    private fun createSHA1DigestBase64Url(bytes : ByteArray) =
        runCatching {
            encode(getInstance("SHA-1").digest(bytes)).toString()
        }.getOrElse {
            throw RuntimeException(it)
        }

    class JwkInvalidException(cause : Throwable) : RuntimeException(cause)
}