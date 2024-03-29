package no.nav.security.token.support.core.validation

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.util.Resource
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTClaimsSet.Builder
import com.nimbusds.jwt.SignedJWT
import java.io.IOException
import java.net.URL
import java.security.KeyPairGenerator
import java.security.NoSuchAlgorithmException
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*
import java.util.concurrent.TimeUnit.HOURS
import no.nav.security.token.support.core.configuration.ProxyAwareResourceRetriever

internal abstract class AbstractJwtValidatorTest {

    private val rsaJwk = setupKeys(KEYID)

    protected fun setupKeys(keyId : String?) =
        try {
             KeyPairGenerator.getInstance("RSA").run {
                initialize(2048) // just for testing so 1024 is ok
                generateKeyPair()
            }.run {
                RSAKey.Builder(public as RSAPublicKey)
                    .privateKey(private as RSAPrivateKey)
                    .keyID(keyId).build()
            }
        }
        catch (e : NoSuchAlgorithmException) {
            throw RuntimeException(e)
        }


    protected fun token(audience : String) = token(listOf(audience))

    protected fun token(audience : List<String?>?) = token(defaultClaims().audience(audience).build())

    protected fun token(claims : JWTClaimsSet) = createSignedJWT(claims).serialize()

    protected fun createSignedJWT(issuer : String, audience : String, sub : String) =
        createSignedJWT(defaultClaims()
            .issuer(issuer)
            .audience(audience)
            .subject(sub)
            .build())

    protected fun defaultClaims() : Builder {
        val now = Date()
        val expiry = Date(now.time + HOURS.toMillis(1))
        return Builder()
            .issuer(DEFAULT_ISSUER)
            .subject(DEFAULT_SUBJECT)
            .jwtID(UUID.randomUUID().toString())
            .notBeforeTime(now)
            .issueTime(now)
            .expirationTime(expiry)
    }

    private fun createSignedJWT(claimsSet : JWTClaimsSet) : SignedJWT {
        try {
            val header = JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(rsaJwk.keyID)
                .type(JOSEObjectType.JWT)
            val signedJWT = SignedJWT(header.build(), claimsSet)
            val signer = RSASSASigner(rsaJwk.toPrivateKey())
            signedJWT.sign(signer)
            return signedJWT
        }
        catch (e : JOSEException) {
            throw RuntimeException(e)
        }
    }

    internal inner class MockResourceRetriever : ProxyAwareResourceRetriever() {

        @Throws(IOException::class)
        override fun retrieveResource(url : URL) : Resource {
            val set = JWKSet(rsaJwk)
            val content = set.toString()
            return Resource(content, "application/json")
        }
    }

    companion object {

        const val DEFAULT_ISSUER  = "https://issuer"
        const val DEFAULT_SUBJECT : String = "foobar"
        private const val KEYID = "myKeyId"
    }
}