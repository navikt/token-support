package no.nav.security.token.support.jaxrs

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.JWKSet.*
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.util.IOUtils
import com.nimbusds.jose.util.IOUtils.*
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.charset.StandardCharsets.*
import java.text.ParseException

internal object JwkGenerator {

    private const val DEFAULT_KEYID = "localhost-signer"
    const val DEFAULT_JWKSET_FILE : String = "/jwkset.json"

    val jWKSet = parse(readInputStreamToString(JwkGenerator::class.java.getResourceAsStream(DEFAULT_JWKSET_FILE), UTF_8))

    val defaultRSAKey = jWKSet.getKeyByKeyId(DEFAULT_KEYID) as RSAKey
}