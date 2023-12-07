package no.nav.security.token.support.core.validation

import java.lang.reflect.Method
import java.util.Arrays
import java.util.Objects
import java.util.Optional
import kotlin.reflect.KClass
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import no.nav.security.token.support.core.api.Protected
import no.nav.security.token.support.core.api.ProtectedWithClaims
import no.nav.security.token.support.core.api.RequiredIssuers
import no.nav.security.token.support.core.api.Unprotected
import no.nav.security.token.support.core.context.TokenValidationContextHolder
import no.nav.security.token.support.core.exceptions.AnnotationRequiredException
import no.nav.security.token.support.core.exceptions.JwtTokenInvalidClaimException
import no.nav.security.token.support.core.exceptions.JwtTokenMissingException
import no.nav.security.token.support.core.jwt.JwtToken
import no.nav.security.token.support.core.utils.Cluster.Companion.currentCluster
import no.nav.security.token.support.core.utils.Cluster.Companion.isProd
import no.nav.security.token.support.core.utils.JwtTokenUtil.contextHasValidToken
import no.nav.security.token.support.core.utils.JwtTokenUtil.getJwtToken

open class JwtTokenAnnotationHandler(private val tokenValidationContextHolder : TokenValidationContextHolder) {

    @Throws(AnnotationRequiredException::class)
    fun assertValidAnnotation(m : Method) : Boolean {
        return Optional.ofNullable(getAnnotation(m, SUPPORTED_ANNOTATIONS))
            .map { a : Annotation -> this.assertValidAnnotation(a) }
            .orElseThrow { AnnotationRequiredException(m) }
    }

    private fun assertValidAnnotation(a : Annotation) : Boolean {
        if (a is Unprotected) {
            LOG.debug("annotation is of type={}, no token validation performed.", Unprotected::class.java.simpleName)
            return true
        }
        if (a is RequiredIssuers) {
            return handleRequiredIssuers(a)
        }
        if (a is ProtectedWithClaims) {
            return handleProtectedWithClaims(a)
        }
        if (a is Protected) {
            return handleProtected()
        }
        LOG.debug("Annotation is unknown,  type={}, no token validation performed. but possible bug so throw exception", a.annotationClass)
        return false
    }

    private fun handleProtected() : Boolean {
        LOG.debug("Annotation is of type={}, check if context has valid token.", Protected::class.simpleName)
        if (contextHasValidToken(tokenValidationContextHolder)) {
            return true
        }
        throw JwtTokenMissingException()
    }

    private fun handleProtectedWithClaims(a : ProtectedWithClaims) : Boolean {
        if (!isProd && Arrays.stream(a.excludedClusters).toList().contains(currentCluster())) {
            LOG.info("Excluding current cluster {} from validation", currentCluster())
            return true
        }
        LOG.debug("Annotation is of type={}, do token validation and claim checking.", ProtectedWithClaims::class.simpleName)
        val jwtToken = getJwtToken(a.issuer, tokenValidationContextHolder)
        if (jwtToken.isEmpty) {
            throw JwtTokenMissingException()
        }

        if (!handleProtectedWithClaimsAnnotation(a, jwtToken.get())) {
            throw JwtTokenInvalidClaimException(a)
        }
        return true
    }

    private fun handleRequiredIssuers(a : RequiredIssuers) : Boolean {
        var hasToken = false
        for (sub in a.value) {
            val jwtToken = getJwtToken(sub.issuer, tokenValidationContextHolder)
            if (jwtToken.isEmpty) {
                continue
            }
            if (handleProtectedWithClaimsAnnotation(sub, jwtToken.get())) {
                return true
            }
            hasToken = true
        }
        if (!hasToken) {
            throw JwtTokenMissingException(a)
        }
        throw JwtTokenInvalidClaimException(a)
    }

    protected open fun getAnnotation(method : Method, types : List<KClass<out Annotation>>) =
        Optional.ofNullable(findAnnotation(types, *method.annotations))
            .orElseGet { findAnnotation(types, *method.declaringClass.annotations) }

    protected fun handleProtectedWithClaimsAnnotation(a : ProtectedWithClaims, jwtToken : JwtToken) : Boolean {
        return handleProtectedWithClaims(a.issuer, a.claimMap, a.combineWithOr, jwtToken)
    }

    protected fun handleProtectedWithClaims(issuer : String, requiredClaims : Array<String>, combineWithOr : Boolean, jwtToken : JwtToken) : Boolean {
        if (issuer.isNotEmpty()) {
            return containsRequiredClaims(jwtToken, combineWithOr, *requiredClaims)
        }
        return true
    }

    protected fun containsRequiredClaims(jwtToken : JwtToken, combineWithOr : Boolean, vararg claims : String) : Boolean {
        LOG.debug("choose matching logic based on combineWithOr={}", combineWithOr)
        return if (combineWithOr) containsAnyClaim(jwtToken, *claims)
        else containsAllClaims(jwtToken, *claims)
    }

    private fun containsAllClaims(jwtToken: JwtToken, vararg claims: String): Boolean {
        if (claims.isNotEmpty()) {
            return claims.asSequence()
                .map { it.split("=", limit = 2) }
                .filter { it.size == 2 }
                .all { (key, value) -> jwtToken.containsClaim(key.trim(), value.trim()) }
        }
        return true
    }

    private fun containsAnyClaim(jwtToken: JwtToken, vararg claims: String): Boolean {
        if (claims.isNotEmpty()) {
            return claims.asSequence()
                .map { it.split("=", limit = 2) }
                .filter { it.size == 2 }
                .any { (key, value) -> jwtToken.containsClaim(key.trim(), value.trim()) }
        }
        LOG.debug("no claims listed, so claim checking is ok.")
        return true
    }

    companion object {

        private val SUPPORTED_ANNOTATIONS = listOf(RequiredIssuers::class, ProtectedWithClaims::class, Protected::class, Unprotected::class)
        protected val LOG : Logger = LoggerFactory.getLogger(JwtTokenAnnotationHandler::class.java)
        private fun findAnnotation(types : List<KClass<out Annotation>>, vararg annotations : Annotation) = annotations.firstOrNull { a -> types.contains(a.annotationClass) }
    }
}