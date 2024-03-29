package no.nav.security.token.support.spring

import no.nav.security.token.support.core.context.TokenValidationContext
import no.nav.security.token.support.core.context.TokenValidationContextHolder
import org.springframework.web.context.request.RequestAttributes.SCOPE_REQUEST
import org.springframework.web.context.request.RequestContextHolder.currentRequestAttributes

class SpringTokenValidationContextHolder : TokenValidationContextHolder {

    private val TOKEN_VALIDATION_CONTEXT_ATTRIBUTE = SpringTokenValidationContextHolder::class.java.name
    override fun getTokenValidationContext() = getRequestAttribute(TOKEN_VALIDATION_CONTEXT_ATTRIBUTE)?.let { it as TokenValidationContext } ?: TokenValidationContext(emptyMap())
    override fun setTokenValidationContext(tokenValidationContext: TokenValidationContext?) = setRequestAttribute(TOKEN_VALIDATION_CONTEXT_ATTRIBUTE, tokenValidationContext)
    private fun getRequestAttribute(name: String) = currentRequestAttributes().getAttribute(name, SCOPE_REQUEST)
    private fun setRequestAttribute(name: String, value: Any?) = value?.let { currentRequestAttributes().setAttribute(name, it, SCOPE_REQUEST) } ?:  currentRequestAttributes().removeAttribute(name, SCOPE_REQUEST)
}