package no.nav.security.token.support.jaxrs;

import no.nav.security.token.support.core.context.TokenValidationContext
import no.nav.security.token.support.core.context.TokenValidationContextHolder

object JaxrsTokenValidationContextHolder : TokenValidationContextHolder {

    private val validationContextHolder = ThreadLocal<TokenValidationContext>()

    fun getHolder() = JWT_BEARER_TOKEN_CONTEXT_HOLDER
    override fun getTokenValidationContext() = validationContextHolder.get()

    override fun setTokenValidationContext(tokenValidationContext: TokenValidationContext?) {

        if (validationContextHolder.get() != null && tokenValidationContext != null) {
            throw IllegalStateException("Should not overwrite the TokenValidationContext")
        }
        validationContextHolder.set(tokenValidationContext)
    }

    private val JWT_BEARER_TOKEN_CONTEXT_HOLDER: TokenValidationContextHolder
    get() = this
}