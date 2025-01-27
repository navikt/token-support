package no.nav.security.token.support.core.validation

import java.lang.reflect.Method
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
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import kotlin.reflect.KClass

open class JwtTokenAnnotationHandler(private val tokenValidationContextHolder : TokenValidationContextHolder) {

    fun assertValidAnnotation(m: Method) =
        getAnnotation(m, SUPPORTED_ANNOTATIONS)?.let { assertValidAnnotation(it) } ?: throw AnnotationRequiredException(m)

    private fun assertValidAnnotation(a: Annotation) =
        when (a) {
            is Unprotected -> true.also { LOG.debug("Annotation is of type={}, no token validation performed.", Unprotected::class.java.simpleName) }
            is RequiredIssuers -> handleRequiredIssuers(a)
            is ProtectedWithClaims -> handleProtectedWithClaims(a)
            is Protected -> handleProtected()
            else -> false.also { LOG.debug("Annotation is unknown, type={}, no token validation performed. but possible bug so throw exception", a.annotationClass) }
        }


    private fun handleProtected()=
        if (contextHasValidToken(tokenValidationContextHolder)) {
            true.also { LOG.debug("Annotation is of type Protected, context has valid token.") }
        }
        else throw JwtTokenMissingException()

    private fun handleProtectedWithClaims(a : ProtectedWithClaims) : Boolean {
        if (!isProd && a.excludedClusters.contains(currentCluster())) {
            LOG.info("Excluding current cluster {} from validation", currentCluster())
            return true
        }
        LOG.debug("Annotation is of type={}, do token validation and claim checking.", ProtectedWithClaims::class.simpleName)
        getJwtToken(a.issuer, tokenValidationContextHolder).run {
            if (isEmpty) {
                throw JwtTokenMissingException()
            }
            if (!handleProtectedWithClaimsAnnotation(a, get())) {
                throw JwtTokenInvalidClaimException(a)
            }
            return true
        }
    }

    private fun handleRequiredIssuers(a: RequiredIssuers): Boolean {
        val hasToken = a.value.any {
            getJwtToken(it.issuer, tokenValidationContextHolder).run {
                isPresent && handleProtectedWithClaimsAnnotation(it, get())
            }
        }
        return when {
            hasToken -> true
            a.value.all { getJwtToken(it.issuer, tokenValidationContextHolder).isEmpty } -> throw JwtTokenMissingException(a)
            else -> throw JwtTokenInvalidClaimException(a)
        }
    }


    protected open fun getAnnotation(method : Method, types : List<KClass<out Annotation>>) =
        findAnnotation(types, *method.annotations) ?: findAnnotation(types, *method.declaringClass.annotations)

    protected fun handleProtectedWithClaimsAnnotation(a : ProtectedWithClaims, jwtToken : JwtToken) = handleProtectedWithClaims(a.issuer, a.claimMap, a.combineWithOr, jwtToken)

    fun handleProtectedWithClaims(issuer : String, requiredClaims : Array<String>, combineWithOr : Boolean, jwtToken : JwtToken) =
        if (issuer.isNotEmpty()) {
            containsRequiredClaims(jwtToken, combineWithOr, *requiredClaims)
        }
        else true

    protected fun containsRequiredClaims(jwtToken : JwtToken, combineWithOr : Boolean, vararg claims : String) : Boolean {
        LOG.debug("choose matching logic based on combineWithOr={}", combineWithOr)
        return if (combineWithOr) containsAnyClaim(jwtToken, *claims)
        else containsAllClaims(jwtToken, *claims)
    }

    private fun containsAllClaims(jwtToken: JwtToken, vararg claims: String) =
        if (claims.isNotEmpty()) {
            claims.asSequence()
                .map { it.split("=", limit = 2) }
                .filter { it.size == 2 }
                .all { (key, value) -> jwtToken.containsClaim(key.trim(), value.trim()) }
        }
        else true

    private fun containsAnyClaim(jwtToken: JwtToken, vararg claims: String) =
        if (claims.isNotEmpty()) {
            claims.asSequence()
                .map { it.split("=", limit = 2) }
                .filter { it.size == 2 }
                .any { (key, value) -> jwtToken.containsClaim(key.trim(), value.trim()) }
        }
        else true.also { LOG.debug("no claims listed, so claim checking is ok.") }

    companion object {

        @JvmField
        val SUPPORTED_ANNOTATIONS = listOf(RequiredIssuers::class, ProtectedWithClaims::class, Protected::class, Unprotected::class)
        protected val LOG : Logger = LoggerFactory.getLogger(JwtTokenAnnotationHandler::class.java)
        private fun findAnnotation(types : List<KClass<out Annotation>>, vararg annotations : Annotation) = annotations.firstOrNull { a -> types.contains(a.annotationClass) }
    }
}