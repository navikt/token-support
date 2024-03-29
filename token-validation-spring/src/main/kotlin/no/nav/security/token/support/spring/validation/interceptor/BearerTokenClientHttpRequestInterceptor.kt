package no.nav.security.token.support.spring.validation.interceptor

import java.io.IOException
import no.nav.security.token.support.core.JwtTokenConstants.AUTHORIZATION_HEADER
import no.nav.security.token.support.core.context.TokenValidationContextHolder
import org.slf4j.LoggerFactory
import org.springframework.http.HttpRequest
import org.springframework.http.client.ClientHttpRequestExecution
import org.springframework.http.client.ClientHttpRequestInterceptor
import org.springframework.http.client.ClientHttpResponse

class BearerTokenClientHttpRequestInterceptor(private val holder: TokenValidationContextHolder) : ClientHttpRequestInterceptor {
    private val log = LoggerFactory.getLogger(BearerTokenClientHttpRequestInterceptor::class.java)

    @Throws(IOException::class)
    override fun intercept(req: HttpRequest, body: ByteArray, execution: ClientHttpRequestExecution): ClientHttpResponse {
        holder.getTokenValidationContext().apply {
            if (hasValidToken()) {
                log.debug("Adding tokens to Authorization header")
                req.headers.add(AUTHORIZATION_HEADER, issuers.joinToString { "${getJwtToken(it)?.asBearer()}" })
            }
            return execution.execute(req, body)
        }
    }
}