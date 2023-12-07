package validation

import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.jwk.source.JWKSourceBuilder
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimNames
import java.net.URL
import java.util.Date
import java.util.concurrent.TimeUnit.SECONDS
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import no.nav.security.token.support.core.exceptions.JwtTokenValidatorException
import no.nav.security.token.support.core.validation.DefaultConfigurableJwtValidator
import no.nav.security.token.support.core.validation.DefaultJwtClaimsVerifier
import no.nav.security.token.support.core.validation.JwtTokenValidator

internal class DefaultConfigurableJwtValidatorTest : AbstractJwtValidatorTest() {

    private val jwksUrl = URL("https://someurl")
    private val jwkSource : JWKSource<SecurityContext> = JWKSourceBuilder.create<SecurityContext>(jwksUrl, MockResourceRetriever()).build()

    @Test
    @Throws(JwtTokenValidatorException::class)
    fun happyPath() {
        val validator = tokenValidator(listOf("aud1"))
        validator.assertValidToken(token("aud1"))
    }

    @Test
    @Throws(JwtTokenValidatorException::class)
    fun happyPathWithOptionalClaims() {
        val acceptedAudiences = listOf("aud1")
        val optionalClaims = java.util.List.of(JWTClaimNames.SUBJECT)
        val validator = tokenValidator(acceptedAudiences, optionalClaims)

        validator.assertValidToken(token("aud1"))
        validator.assertValidToken(token(defaultClaims()
            .audience("aud1")
            .subject(null)
            .build())
                                  )
    }

    @Test
    @Throws(JwtTokenValidatorException::class)
    fun missingRequiredClaims() {
        val aud = listOf("aud1")
        val validator = tokenValidator(aud)

        Assertions.assertThrows(JwtTokenValidatorException::class.java, {
            val claims = defaultClaims()
                .issuer(null)
                .audience(aud)
                .build()
            validator.assertValidToken(token(claims))
        }, "missing default required issuer claim")

        Assertions.assertThrows(JwtTokenValidatorException::class.java, {
            val claims = defaultClaims()
                .subject(null)
                .audience(aud)
                .build()
            validator.assertValidToken(token(claims))
        }, "missing default required subject claim")

        Assertions.assertThrows(JwtTokenValidatorException::class.java, {
            val claims = defaultClaims()
                .audience(emptyList())
                .build()
            validator.assertValidToken(token(claims))
        }, "missing default required audience claim")

        Assertions.assertThrows(JwtTokenValidatorException::class.java, {
            val claims = defaultClaims()
                .audience(aud)
                .expirationTime(null)
                .build()
            validator.assertValidToken(token(claims))
        }, "missing default required expiration time claim")

        Assertions.assertThrows(JwtTokenValidatorException::class.java, {
            val claims = defaultClaims()
                .audience(aud)
                .issueTime(null)
                .build()
            validator.assertValidToken(token(claims))
        }, "missing default required issued at claim")
    }

    @Test
    @Throws(JwtTokenValidatorException::class)
    fun atLeastOneAudienceMustMatch() {
        val validator = tokenValidator(listOf("aud1"))
        validator.assertValidToken(token("aud1"))
        validator.assertValidToken(token(listOf("aud1", "aud2")))
        Assertions.assertThrows(JwtTokenValidatorException::class.java,
            { validator.assertValidToken(token(listOf("aud2", "aud3"))) },
            "at least one audience must match accepted audiences")
    }

    @Test
    @Throws(JwtTokenValidatorException::class)
    fun multipleAcceptedAudiences() {
        val acceptedAudiences = listOf("aud1", "aud2")
        val validator = tokenValidator(acceptedAudiences)
        validator.assertValidToken(token("aud1"))
        validator.assertValidToken(token("aud2"))
        validator.assertValidToken(token(listOf("aud1", "aud2")))
        Assertions.assertThrows(JwtTokenValidatorException::class.java, { validator.assertValidToken(token("aud3")) }, "unknown audience should be rejected")
    }

    @Test
    @Throws(JwtTokenValidatorException::class)
    fun noAcceptedAudiences() {
        val acceptedAudiences = emptyList<String>()
        val validator = tokenValidator(acceptedAudiences)
        Assertions.assertThrows(JwtTokenValidatorException::class.java, { validator.assertValidToken(token("aud1")) }, "unknown audience should be rejected")
        Assertions.assertThrows(JwtTokenValidatorException::class.java,
            { validator.assertValidToken(token(emptyList<String>())) },
            "missing required audience claim")
        Assertions.assertThrows(JwtTokenValidatorException::class.java, {
            validator.assertValidToken(token(
                (null as String?)!!))
        }, "missing required audience claim")
    }

    @Test
    @Throws(JwtTokenValidatorException::class)
    fun optionalAudienceWithAcceptedAudiencesOnlyDisablesAudienceExistenceCheck() {
        val acceptedAudiences = listOf("aud1")
        val optionalClaims = java.util.List.of(JWTClaimNames.AUDIENCE)
        val validator = tokenValidator(acceptedAudiences, optionalClaims)

        validator.assertValidToken(token("aud1"))
        Assertions.assertThrows(JwtTokenValidatorException::class.java, { validator.assertValidToken(token("not-aud1")) }, "should reject invalid audience")
        validator.assertValidToken(token(emptyList<String>()))
        validator.assertValidToken(token(defaultClaims().build()))
        validator.assertValidToken(token(defaultClaims().audience(null as String?).build()))
        validator.assertValidToken(token(defaultClaims().audience(emptyList()).build()))
    }

    @Test
    @Throws(JwtTokenValidatorException::class)
    fun optionalAudienceWithNoAcceptedAudiencesDisablesAudienceValidation() {
        val acceptedAudiences = emptyList<String>()
        val optionalClaims = java.util.List.of(JWTClaimNames.AUDIENCE)
        val validator = tokenValidator(acceptedAudiences, optionalClaims)

        validator.assertValidToken(token("aud1"))
        validator.assertValidToken(token("not-aud1"))
        validator.assertValidToken(token(emptyList<String>()))
        validator.assertValidToken(token(defaultClaims().build()))
        validator.assertValidToken(token(defaultClaims().audience(null as String?).build()))
        validator.assertValidToken(token(defaultClaims().audience(emptyList()).build()))
    }

    @Test
    @Throws(JwtTokenValidatorException::class)
    fun issuerMismatch() {
        val aud = listOf("aud1")
        val validator = tokenValidator(aud)
        Assertions.assertThrows(JwtTokenValidatorException::class.java) {
            val token = token(defaultClaims()
                .audience(aud)
                .issuer("invalid-issuer")
                .build())
            validator.assertValidToken(token)
        }
    }

    @Test
    @Throws(JwtTokenValidatorException::class)
    fun missingNbfShouldNotFail() {
        val acceptedAudiences = listOf("aud1")
        val validator = tokenValidator(acceptedAudiences)
        val token = token(defaultClaims()
            .audience(acceptedAudiences)
            .notBeforeTime(null)
            .build())
        validator.assertValidToken(token)
    }

    @Test
    @Throws(JwtTokenValidatorException::class)
    fun expBeforeNowShouldFail() {
        val acceptedAudiences = listOf("aud1")
        val validator = tokenValidator(acceptedAudiences)
        val now = Date()
        val beforeNow = Date(now.time - maxClockSkewMillis())
        val token = token(defaultClaims()
            .audience(acceptedAudiences)
            .expirationTime(beforeNow)
            .build())
        Assertions.assertThrows(JwtTokenValidatorException::class.java) { validator.assertValidToken(token) }
    }

    @Test
    @Throws(JwtTokenValidatorException::class)
    fun iatAfterNowShouldFail() {
        val acceptedAudiences = listOf("aud1")
        val validator = tokenValidator(acceptedAudiences)
        val now = Date()
        val afterNow = Date(now.time + maxClockSkewMillis())
        val token = token(defaultClaims()
            .audience(acceptedAudiences)
            .issueTime(afterNow)
            .build())
        Assertions.assertThrows(JwtTokenValidatorException::class.java) { validator.assertValidToken(token) }
    }

    @Test
    @Throws(JwtTokenValidatorException::class)
    fun nbfAfterNowShouldFail() {
        val acceptedAudiences = listOf("aud1")
        val validator = tokenValidator(acceptedAudiences)
        val now = Date()
        val afterNow = Date(now.time + maxClockSkewMillis())
        val token = token(defaultClaims()
            .audience(acceptedAudiences)
            .notBeforeTime(afterNow)
            .build())
        Assertions.assertThrows(JwtTokenValidatorException::class.java) { validator.assertValidToken(token) }
    }

    private fun tokenValidator(acceptedAudiences : List<String>) : JwtTokenValidator {
        return DefaultConfigurableJwtValidator(DEFAULT_ISSUER, acceptedAudiences, emptyList(), jwkSource)
    }

    private fun tokenValidator(acceptedAudiences : List<String>, optionalClaims : List<String>) : JwtTokenValidator {
        return DefaultConfigurableJwtValidator(DEFAULT_ISSUER, acceptedAudiences, optionalClaims, jwkSource)
    }

    private fun maxClockSkewMillis() : Long {
        return SECONDS.toMillis((DefaultJwtClaimsVerifier.DEFAULT_MAX_CLOCK_SKEW_SECONDS + 5).toLong())
    }
}