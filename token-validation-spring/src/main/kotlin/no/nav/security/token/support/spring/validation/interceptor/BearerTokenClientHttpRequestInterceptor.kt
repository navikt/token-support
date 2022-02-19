package no.nav.security.token.support.spring.validation.interceptor

import no.nav.security.token.support.core.context.TokenValidationContextHolder
import org.springframework.http.client.ClientHttpRequestInterceptor
import kotlin.Throws
import java.io.IOException
import org.springframework.http.client.ClientHttpRequestExecution
import no.nav.security.token.support.core.JwtTokenConstants.*
import org.slf4j.LoggerFactory
import org.springframework.http.HttpRequest
import org.springframework.http.client.ClientHttpResponse

class BearerTokenClientHttpRequestInterceptor(private val holder: TokenValidationContextHolder) : ClientHttpRequestInterceptor {
    private val log = LoggerFactory.getLogger(BearerTokenClientHttpRequestInterceptor::class.java)

    @Throws(IOException::class)
    override fun intercept(req: HttpRequest, body: ByteArray, execution: ClientHttpRequestExecution): ClientHttpResponse {
        holder.tokenValidationContext?.let { c ->
            if (c.hasValidToken()) {
                log.debug("Adding tokens to Authorization header")
                req.headers.add(AUTHORIZATION_HEADER, c.issuers.joinToString(transform = { "Bearer " + c.getJwtToken(it).tokenAsString }))
            }
        } ?: log.debug("no tokens found, nothing added to request")
        return execution.execute(req, body)
    }
}