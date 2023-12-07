package no.nav.security.token.support.core.validation

import com.nimbusds.jwt.JWTClaimsSet.Builder
import com.nimbusds.jwt.PlainJWT
import java.util.Arrays
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import no.nav.security.token.support.core.context.TokenValidationContext
import no.nav.security.token.support.core.context.TokenValidationContextHolder
import no.nav.security.token.support.core.jwt.JwtToken

internal class JwtTokenAnnotationHandlerTest {

    private val annotationHandler : JwtTokenAnnotationHandler

    init {
        val validationContextMap : MutableMap<String, JwtToken> = HashMap()
        validationContextMap["issuer1"] = T1
        validationContextMap["issuer2"] = T2
        validationContextMap["issuer3"] = T3
        validationContextMap["issuer4"] = T4

        val tokenValidationContextHolder = object : TokenValidationContextHolder {
            override fun getTokenValidationContext() = TokenValidationContext(validationContextMap)
            override fun setTokenValidationContext(tokenValidationContext : TokenValidationContext?) {}
        }
        this.annotationHandler = JwtTokenAnnotationHandler(tokenValidationContextHolder)
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

        private fun jwtToken(issuer : String, vararg claims : String) : JwtToken {
            val builder = Builder()
                .issuer(issuer)
                .subject("subject")
            Arrays.stream(claims).map { c : String ->
                c.split("=".toRegex()).dropLastWhile { it.isEmpty() }
                    .toTypedArray()
            }.forEach { pair : Array<String> ->
                builder.claim(pair[0], pair[1])
            }
            val plainJWT = PlainJWT(builder.build())
            return JwtToken(plainJWT.serialize())
        }
    }
}