package no.nav.security.token.support.spring.integrationtest

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.JWKSet.*
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.RSAKey.Builder
import com.nimbusds.jose.util.IOUtils
import java.io.File
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.charset.StandardCharsets.*
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.NoSuchAlgorithmException
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.text.ParseException


object JwkGenerator {
    const val DEFAULT_KEYID = "localhost-signer"
    private const val DEFAULT_JWKSET_FILE = "/jwkset.json"

    val jWKSet =
        try {
            parse(IOUtils.readInputStreamToString(JwkGenerator::class.java.getResourceAsStream(DEFAULT_JWKSET_FILE), UTF_8))
        } catch (e: Exception) {
            throw RuntimeException(e)
        }
    val defaultRSAKey: RSAKey get() = jWKSet.getKeyByKeyId(DEFAULT_KEYID) as RSAKey

    fun generateKeyPair() =
         try {
            val gen = KeyPairGenerator.getInstance("RSA")
            gen.initialize(2048)
            gen.generateKeyPair()
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException(e)
        }


    fun createJWK(keyID: String?, keyPair: KeyPair) =
         Builder(keyPair.public as RSAPublicKey)
            .privateKey(keyPair.private as RSAPrivateKey)
            .keyID(keyID)
            .build()
}