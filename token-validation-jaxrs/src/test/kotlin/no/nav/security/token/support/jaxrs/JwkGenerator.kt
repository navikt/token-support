package no.nav.security.token.support.jaxrs

import com.nimbusds.jose.jwk.JWKSet.parse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.util.IOUtils.readInputStreamToString
import java.nio.charset.StandardCharsets.UTF_8

internal object JwkGenerator {

    private const val DEFAULT_KEYID = "localhost-signer"
    const val DEFAULT_JWKSET_FILE : String = "/jwkset.json"

    val jWKSet = parse(readInputStreamToString(JwkGenerator::class.java.getResourceAsStream(DEFAULT_JWKSET_FILE), UTF_8))

    val defaultRSAKey = jWKSet.getKeyByKeyId(DEFAULT_KEYID) as RSAKey
}