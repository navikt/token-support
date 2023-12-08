package no.nav.security.token.support.core.context;

interface TokenValidationContextHolder {

    fun getTokenValidationContext() : TokenValidationContext

    fun setTokenValidationContext(tokenValidationContext: TokenValidationContext?)
}