package no.nav.security.token.support.filter

import jakarta.servlet.DispatcherType
import jakarta.servlet.DispatcherType.*
import jakarta.servlet.Filter
import jakarta.servlet.FilterChain
import jakarta.servlet.FilterConfig
import jakarta.servlet.RequestDispatcher.ERROR_EXCEPTION
import jakarta.servlet.RequestDispatcher.ERROR_MESSAGE
import jakarta.servlet.ServletRequest
import jakarta.servlet.ServletResponse
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import no.nav.security.token.support.core.context.TokenValidationContextHolder
import no.nav.security.token.support.core.http.HttpRequest
import no.nav.security.token.support.core.validation.JwtTokenValidationHandler
import org.slf4j.LoggerFactory

open class JwtTokenValidationFilter(private val jwtTokenValidationHandler : JwtTokenValidationHandler, private val contextHolder : TokenValidationContextHolder) : Filter {
    private val log = LoggerFactory.getLogger(JwtTokenValidationFilter::class.java)
    override fun destroy() {}

    override fun doFilter(request : ServletRequest, response : ServletResponse, chain : FilterChain) {
        if (request is HttpServletRequest) {
            if (request.dispatcherType == ASYNC &&(request.getAttribute(ERROR_EXCEPTION) as? Throwable)?.message?.contains("broken pipe", ignoreCase = true) == true) {
                log.trace("Skipping token validation for async request, client is gone")
                chain.doFilter(request, response)
            }
            else {
                doTokenValidation(request, response as HttpServletResponse, chain)
            }
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
        }
    }
}