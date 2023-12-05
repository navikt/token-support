package no.nav.security.token.support.core.context;


import kotlin.Unit;
import kotlin.reflect.KFunction;

interface TokenValidationContextHolder {

    fun getTokenValidationContext() : TokenValidationContext

    fun setTokenValidationContext(tokenValidationContext: TokenValidationContext?)
}