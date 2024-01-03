package no.nav.security.token.support.spring.validation.interceptor

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import java.util.concurrent.ConcurrentHashMap
import org.slf4j.LoggerFactory
import org.springframework.core.annotation.AnnotationAttributes
import org.springframework.http.HttpStatus.NOT_IMPLEMENTED
import org.springframework.web.method.HandlerMethod
import org.springframework.web.server.ResponseStatusException
import org.springframework.web.servlet.HandlerInterceptor
import no.nav.security.token.support.core.exceptions.AnnotationRequiredException
import no.nav.security.token.support.core.validation.JwtTokenAnnotationHandler

class JwtTokenHandlerInterceptor(attrs: AnnotationAttributes?, private val h: JwtTokenAnnotationHandler) : HandlerInterceptor {
    private val log = LoggerFactory.getLogger(JwtTokenHandlerInterceptor::class.java)
    private val handlerFlags: MutableMap<Any, Boolean> = ConcurrentHashMap()
    private val ignoreConfig = attrs?.getStringArray("ignore") ?: arrayOfNulls(0) ?: arrayOfNulls(0)

    override fun preHandle(request: HttpServletRequest, response: HttpServletResponse, handler: Any): Boolean {
        if (handler is HandlerMethod) {
            return if (shouldIgnore(handler.bean)) {
                true
            }
            else try {
                h.assertValidAnnotation(handler.method)
            } catch (e: AnnotationRequiredException) {
                log.warn("Received AnnotationRequiredException from JwtTokenAnnotationHandler. return status=$NOT_IMPLEMENTED", e)
                throw ResponseStatusException(NOT_IMPLEMENTED, "Endpoint not accessible")
            } catch (e: Exception) {
                throw JwtTokenUnauthorizedException(cause = e)
            }
        }
        log.debug("Handler is of type ${handler.javaClass.simpleName}, allowing unprotected access to the resources it accesses")
        return true
    }

    private fun shouldIgnore(o: Any): Boolean {
        val fullName = o.javaClass.name
        val ignore = ignoreConfig.any { fullName.startsWith(it) }
        log.trace("Adding $fullName to OIDC validation ${if (ignore) "ignore" else "interceptor"} list")
        handlerFlags[o] = ignore
        return ignore
    }
}