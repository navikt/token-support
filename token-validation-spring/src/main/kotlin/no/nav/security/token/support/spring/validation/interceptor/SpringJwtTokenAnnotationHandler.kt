package no.nav.security.token.support.spring.validation.interceptor

import java.lang.reflect.AnnotatedElement
import java.lang.reflect.Method
import no.nav.security.token.support.core.context.TokenValidationContextHolder
import no.nav.security.token.support.core.validation.JwtTokenAnnotationHandler
import org.springframework.core.annotation.AnnotatedElementUtils.findMergedAnnotation
import kotlin.reflect.KClass

class SpringJwtTokenAnnotationHandler(holder: TokenValidationContextHolder) : JwtTokenAnnotationHandler(holder) {
    override fun getAnnotation(method: Method, types: List<KClass<out Annotation>>)  =
        findAnnotation(method, types) ?: findAnnotation(method.declaringClass, types)

    private fun findAnnotation(e: AnnotatedElement, types: List<KClass<out Annotation>>) =
        types.firstNotNullOfOrNull { findMergedAnnotation(e, it.java) }
}