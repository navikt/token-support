package no.nav.security.token.support.spring.integrationtest

import com.nimbusds.jose.jwk.RSAKey.Builder
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.NoSuchAlgorithmException
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

object JwkGenerator {
    const val DEFAULT_KEYID = "localhost-signer"

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