package no.nav.security.token.support.filter

import jakarta.servlet.Filter
import jakarta.servlet.FilterChain
import jakarta.servlet.FilterConfig
import jakarta.servlet.ServletRequest
import jakarta.servlet.ServletResponse
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import no.nav.security.token.support.core.context.TokenValidationContext
import no.nav.security.token.support.core.context.TokenValidationContextHolder
import no.nav.security.token.support.core.http.HttpRequest
import no.nav.security.token.support.core.http.HttpRequest.NameValue
import no.nav.security.token.support.core.validation.JwtTokenValidationHandler

open class JwtTokenValidationFilter(private val jwtTokenValidationHandler : JwtTokenValidationHandler, private val contextHolder : TokenValidationContextHolder) : Filter {

    override fun destroy() {}

    override fun doFilter(request : ServletRequest, response : ServletResponse, chain : FilterChain) {
        if (request is HttpServletRequest) {
            doTokenValidation(request, response as HttpServletResponse, chain)
        }
        else {
            chain.doFilter(request, response)
        }
    }

    override fun init(filterConfig : FilterConfig) {}

    private fun doTokenValidation(request : HttpServletRequest, response : HttpServletResponse, chain : FilterChain) {
        contextHolder.setTokenValidationContext(jwtTokenValidationHandler.getValidatedTokens(fromHttpServletRequest(request)))
        try {
            chain.doFilter(request, response)
        }
        finally {
            contextHolder.setTokenValidationContext(null)
        }
    }

    companion object {

        @JvmStatic
        fun fromHttpServletRequest(request: HttpServletRequest) = object : HttpRequest {
            override fun getHeader(headerName: String) = request.getHeader(headerName)
            override fun getCookies() : Array<NameValue>? = request.cookies?.map {
                object : NameValue {
                    override fun getName() = it.name
                    override fun getValue() = it.value
                }
            }?.toTypedArray()
        }
    }
}