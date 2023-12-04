package no.nav.security.token.support.core.utils

import no.nav.security.token.support.core.context.TokenValidationContextHolder

object JwtTokenUtil {

   @JvmStatic
    fun contextHasValidToken(holder : TokenValidationContextHolder?) = context(holder).hasValidToken()
    @JvmStatic
    fun getJwtToken(issuer : String, holder : TokenValidationContextHolder?) = context(holder).getJwtTokenAsOptional(issuer)

    private fun context(holder : TokenValidationContextHolder?) = holder?.getTokenValidationContext() ?: throw IllegalStateException("TokenValidationContextHolder is null")
}