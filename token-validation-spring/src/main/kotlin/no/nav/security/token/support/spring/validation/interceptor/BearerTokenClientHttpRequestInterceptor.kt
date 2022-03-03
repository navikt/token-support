package no.nav.security.token.support.spring.validation.interceptor

import no.nav.security.token.support.core.JwtTokenConstants.AUTHORIZATION_HEADER
import no.nav.security.token.support.core.context.TokenValidationContextHolder
import org.slf4j.LoggerFactory
import org.springframework.http.HttpRequest
import org.springframework.http.client.ClientHttpRequestExecution
import org.springframework.http.client.ClientHttpRequestInterceptor
import org.springframework.http.client.ClientHttpResponse
import java.io.IOException

class BearerTokenClientHttpRequestInterceptor(private val holder: TokenValidationContextHolder,
                                              private val enabled: Boolean = true) : ClientHttpRequestInterceptor {
    private val log = LoggerFactory.getLogger(BearerTokenClientHttpRequestInterceptor::class.java)

    @Throws(IOException::class)
    override fun intercept(req: HttpRequest,
                           body: ByteArray,
                           execution: ClientHttpRequestExecution): ClientHttpResponse {
        if (enabled) {
            holder.tokenValidationContext?.apply {
                if (hasValidToken()) {
                    log.debug("Adding tokens to Authorization header")
                    req.headers.add(
                            AUTHORIZATION_HEADER,
                            issuers.joinToString { "Bearer " + getJwtToken(it).tokenAsString })
                }
            } ?: log.debug("no tokens found, nothing added to request")
        }
        else {
            log.trace("is disabled, no bearer propagated, make sure it is propagated by another means")
        }
        return execution.execute(req, body)
    }
}