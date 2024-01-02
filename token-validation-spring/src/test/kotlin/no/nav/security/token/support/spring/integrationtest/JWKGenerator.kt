package no.nav.security.token.support.spring.integrationtest

import com.nimbusds.jose.jwk.RSAKey.Builder
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

object JwkGenerator {
    const val DEFAULT_KEYID = "localhost-signer"

    fun generateKeyPair() =
         runCatching {
            KeyPairGenerator.getInstance("RSA").apply {
                initialize(2048)
            }.genKeyPair()
        }.getOrThrow()


    fun createJWK(keyID: String, keyPair: KeyPair) =
         Builder(keyPair.public as RSAPublicKey)
            .privateKey(keyPair.private as RSAPrivateKey)
            .keyID(keyID)
            .build()
}