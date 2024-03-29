package no.nav.security.token.support.jaxrs

import jakarta.inject.Inject
import jakarta.ws.rs.client.ClientRequestContext
import jakarta.ws.rs.client.ClientRequestFilter
import no.nav.security.token.support.core.JwtTokenConstants.AUTHORIZATION_HEADER
import no.nav.security.token.support.jaxrs.JaxrsTokenValidationContextHolder.getHolder
import org.slf4j.Logger
import org.slf4j.LoggerFactory

class JwtTokenClientRequestFilter @Inject constructor() : ClientRequestFilter {

    override fun filter(requestContext : ClientRequestContext) {
        val context = getHolder().getTokenValidationContext()

        if (context.hasValidToken()) {
            LOG.debug("Adding tokens to Authorization header")
            val headerValue = context.issuers.joinToString(separator = "") {
                LOG.debug("Adding token for issuer $it")
                "Bearer ${context.getJwtToken(it)?.encodedToken}"
            }
            requestContext.headers[AUTHORIZATION_HEADER] = listOf(headerValue)
        } else {
            LOG.debug("No tokens found, nothing added to request")
        }
    }

    companion object {

        private val LOG : Logger = LoggerFactory.getLogger(JwtTokenClientRequestFilter::class.java)
    }
}