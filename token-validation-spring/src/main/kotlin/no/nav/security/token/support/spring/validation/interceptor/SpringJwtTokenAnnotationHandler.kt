package no.nav.security.token.support.spring.validation.interceptor

import no.nav.security.token.support.core.context.TokenValidationContextHolder
import no.nav.security.token.support.core.validation.JwtTokenAnnotationHandler
import org.springframework.core.annotation.AnnotatedElementUtils.findMergedAnnotation
import java.lang.reflect.AnnotatedElement
import java.lang.reflect.Method
import java.util.*


class SpringJwtTokenAnnotationHandler(holder: TokenValidationContextHolder?) : JwtTokenAnnotationHandler(holder) {
    override fun getAnnotation(m: Method, types: List<Class<out Annotation>>): Annotation? = Optional.ofNullable(findAnnotation(m, types))
        .orElseGet { findAnnotation(m.declaringClass, types) }

    private fun findAnnotation(e: AnnotatedElement, types: List<Class<out Annotation>>): Annotation? {
        return types.stream()
            .map { t: Class<out Annotation> -> findMergedAnnotation(e, t) }
            .filter { Objects.nonNull(it) }
            .findFirst()
            .orElse(null)
    }
}