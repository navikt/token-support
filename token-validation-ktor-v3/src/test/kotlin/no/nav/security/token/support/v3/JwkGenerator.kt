package no.nav.security.token.support.v3

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.util.IOUtils
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.text.ParseException


object JwkGenerator {
    const val DEFAULT_KEYID = "localhost-signer"
    const val DEFAULT_JWKSET_FILE = "/jwkset.json"
    val defaultRSAKey: RSAKey
        get() = jWKSet.getKeyByKeyId(DEFAULT_KEYID) as RSAKey

    val jWKSet: JWKSet
        get() = try {
            JWKSet.parse(
                    IOUtils.readInputStreamToString(
                            JwkGenerator::class.java.getResourceAsStream(DEFAULT_JWKSET_FILE), StandardCharsets.UTF_8))
        } catch (io: IOException) {
            throw RuntimeException(io)
        } catch (io: ParseException) {
            throw RuntimeException(io)
        }

}
