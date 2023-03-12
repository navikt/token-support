package no.nav.security.token.support.spring.validation.interceptor

import java.lang.reflect.AnnotatedElement
import java.lang.reflect.Method
import no.nav.boot.conditionals.Cluster.Companion.currentCluster
import no.nav.boot.conditionals.EnvUtil.isProd
import no.nav.security.token.support.core.context.TokenValidationContextHolder
import no.nav.security.token.support.core.validation.JwtTokenAnnotationHandler
import no.nav.security.token.support.spring.ProtectedRestController
import org.springframework.core.annotation.AnnotatedElementUtils.findMergedAnnotation
import org.springframework.core.env.Environment

class SpringJwtTokenAnnotationHandler(holder: TokenValidationContextHolder?, private val env: Environment) : JwtTokenAnnotationHandler(holder) {
    override fun getAnnotation(m: Method, types: List<Class<out Annotation>>)  =
        findAnnotation(m, types) ?: findAnnotation(m.declaringClass, types)

    private fun findAnnotation(e: AnnotatedElement, types: List<Class<out Annotation>>) =
        types.firstNotNullOfOrNull { t: Class<out Annotation> -> findMergedAnnotation(e, t) }

    override fun assertValidAnnotation(a: Annotation): Boolean =
        when(a) {
            is ProtectedRestController -> {
               if (currentCluster() in a.excludedClusters) {
                   if (isProd(env)) {
                       LOG.warn("${currentCluster()} excluded from token validation is a prod cluster, is this really what you want?")
                   }
                   LOG.info("${a.javaClass.simpleName} excludes token validation in ${currentCluster()}")
                   true
               }
               else {
                   super.assertValidAnnotation(a)
               }
            }
            else -> super.assertValidAnnotation(a)
        }
}