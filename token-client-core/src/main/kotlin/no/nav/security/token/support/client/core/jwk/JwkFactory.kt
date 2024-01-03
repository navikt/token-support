package no.nav.security.token.support.client.core.jwk

import com.nimbusds.jose.jwk.JWKSet.load
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.RSAKey.Builder
import com.nimbusds.jose.jwk.RSAKey.parse
import com.nimbusds.jose.util.Base64URL.encode
import java.io.InputStream
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.Files.readString
import java.nio.file.Path.of
import java.security.KeyStore
import java.security.MessageDigest.getInstance

object JwkFactory {

    @JvmStatic
    fun fromJsonFile(filePath : String) =
        runCatching {
            fromJson(readString(of(filePath).toAbsolutePath(), UTF_8))
        }.getOrElse {
            throw JwkInvalidException(it)
        }


    @JvmStatic
    fun fromJson(jwk : String) =
        runCatching {
            parse(jwk)
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
                    load(this@run) { this }
                }
            }
        }.getOrElse {
            throw RuntimeException(it)
        }


    private fun getX509CertSHA1Thumbprint(rsaKey: RSAKey) =
        runCatching {
            rsaKey.parsedX509CertChain.firstOrNull()?.let { cert ->
                createSHA1DigestBase64Url(cert.encoded)
            }
        }.getOrElse { throw RuntimeException(it) }

    private fun createSHA1DigestBase64Url(bytes : ByteArray) =
        runCatching {
            "${encode(getInstance("SHA-1").digest(bytes))}"
        }.getOrElse {
            throw RuntimeException(it)
        }

    class JwkInvalidException(cause : Throwable) : RuntimeException(cause)
}