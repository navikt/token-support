package no.nav.security.token.support.core.validation

import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.PlainJWT
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import no.nav.security.token.support.core.context.TokenValidationContext
import no.nav.security.token.support.core.context.TokenValidationContextHolder
import no.nav.security.token.support.core.jwt.JwtToken

internal class JwtTokenAnnotationHandlerTest {

    private val annotationHandler : JwtTokenAnnotationHandler

    init {
        val validationContextMap  = HashMap<String, JwtToken>().apply {
            put("issuer1", T1)
            put("issuer2", T2)
            put("issuer3", T3)
            put("issuer4", T4)        }

        annotationHandler = JwtTokenAnnotationHandler(object : TokenValidationContextHolder {
            override fun getTokenValidationContext() = TokenValidationContext(validationContextMap)
            override fun setTokenValidationContext(tokenValidationContext : TokenValidationContext?) {}
        })
    }

    @Test
    fun checkThatAlternativeClaimsWithSameKeyWorks() {
        val protectedWithAnyClaim = arrayOf("acr=Level3", "acr=Level4") // Require either acr=Level3 or acr=Level4
        assertTrue(annotationHandler.handleProtectedWithClaims("issuer1", protectedWithAnyClaim, true, T1))
        assertTrue(annotationHandler.handleProtectedWithClaims("issuer2", protectedWithAnyClaim, true, T2))
        assertFalse(annotationHandler.handleProtectedWithClaims("issuer3", protectedWithAnyClaim, true, T3))
        assertTrue(annotationHandler.handleProtectedWithClaims("issuer4", protectedWithAnyClaim, true, T4))
    }

    @Test
    fun checkThatMultipleRequiredClaimsWorks() {
        val protectedWithAllClaims = arrayOf("acr=Level3", "foo=bar") // Require acr=Level3 and foo=bar
        assertFalse(annotationHandler.handleProtectedWithClaims("issuer1", protectedWithAllClaims, false, T1))
        assertFalse(annotationHandler.handleProtectedWithClaims("issuer2", protectedWithAllClaims, false, T2))
        assertFalse(annotationHandler.handleProtectedWithClaims("issuer3", protectedWithAllClaims, false, T3))
        assertTrue(annotationHandler.handleProtectedWithClaims("issuer4", protectedWithAllClaims, false, T4))
    }

    @Test
    fun checkThatClaimWithUnknownValueIsRejected() {
        val protectedWithClaims = arrayOf("acr=Level3", "acr=Level4")
        // Token from issuer3 only contains acr=Level1
        assertFalse(annotationHandler.handleProtectedWithClaims("issuer3", protectedWithClaims, true, T3))
        assertFalse(annotationHandler.handleProtectedWithClaims("issuer3", protectedWithClaims, false, T3))
    }

    @Test
    fun chechThatNoReqiredClaimsWorks() {
        val protectedWithClaims = arrayOf<String>()
        assertTrue(annotationHandler.handleProtectedWithClaims("issuer1", protectedWithClaims, true, T1))
        assertTrue(annotationHandler.handleProtectedWithClaims("issuer2", protectedWithClaims, true, T2))
        assertTrue(annotationHandler.handleProtectedWithClaims("issuer3", protectedWithClaims, true, T3))
        assertTrue(annotationHandler.handleProtectedWithClaims("issuer4", protectedWithClaims, true, T4))
        assertTrue(annotationHandler.handleProtectedWithClaims("issuer1", protectedWithClaims, false, T1))
        assertTrue(annotationHandler.handleProtectedWithClaims("issuer2", protectedWithClaims, false, T2))
        assertTrue(annotationHandler.handleProtectedWithClaims("issuer3", protectedWithClaims, false, T3))
        assertTrue(annotationHandler.handleProtectedWithClaims("issuer4", protectedWithClaims, false, T4))
    }

    companion object {

        private val T1 = jwtToken("https://one", "acr=Level3")
        private val T2 = jwtToken("https://two", "acr=Level4")
        private val T3 = jwtToken("https://three", "acr=Level1")
        private val T4 = jwtToken("https://four", "acr=Level3", "foo=bar")

        private fun jwtToken(issuer: String, vararg claims: String): JwtToken {
            val builder = JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject("subject")

            claims.forEach {
                val parts = it.split("=")
                if (parts.size == 2) {
                    builder.claim(parts[0], parts[1])
                }
            }
            return JwtToken(PlainJWT(builder.build()).serialize())
        }
    }
}