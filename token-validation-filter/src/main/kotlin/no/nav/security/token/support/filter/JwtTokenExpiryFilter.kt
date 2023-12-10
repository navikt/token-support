package no.nav.security.token.support.filter

import com.nimbusds.jwt.JWTClaimNames
import com.nimbusds.jwt.JWTClaimNames.*
import jakarta.servlet.Filter
import jakarta.servlet.FilterChain
import jakarta.servlet.FilterConfig
import jakarta.servlet.ServletRequest
import jakarta.servlet.ServletResponse
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.temporal.ChronoUnit.MINUTES
import java.util.Date
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import no.nav.security.token.support.core.JwtTokenConstants
import no.nav.security.token.support.core.context.TokenValidationContextHolder
import no.nav.security.token.support.core.jwt.JwtTokenClaims

/**
 * Checks the expiry time in a validated token against a preconfigured threshold
 * and returns a custom http header if this threshold is reached.
 *
 *
 * Can be used to check if the token is about to expire and inform the caller
 */
class JwtTokenExpiryFilter(private val contextHolder : TokenValidationContextHolder, private val expiryThresholdInMinutes : Long) : Filter {

    override fun doFilter(request : ServletRequest, response : ServletResponse, chain : FilterChain) {
        if (request is HttpServletRequest) {
            addHeaderOnTokenExpiryThreshold(response as HttpServletResponse)
            chain.doFilter(request, response)
        }
        else {
            chain.doFilter(request, response)
        }
    }

    override fun destroy() {}

    override fun init(filterConfig : FilterConfig) {}

    private fun addHeaderOnTokenExpiryThreshold(response : HttpServletResponse) {
        val tokenValidationContext = contextHolder.getTokenValidationContext()
        LOG.debug("Getting TokenValidationContext: {}", tokenValidationContext)
        if (tokenValidationContext != null) {
            LOG.debug("Getting issuers from validationcontext {}", tokenValidationContext.issuers)
            for (issuer in tokenValidationContext.issuers) {
                val jwtTokenClaims = tokenValidationContext.getClaims(issuer)
                if (tokenExpiresBeforeThreshold(jwtTokenClaims)) {
                    LOG.debug("Setting response header {}", JwtTokenConstants.TOKEN_EXPIRES_SOON_HEADER)
                    response.setHeader(JwtTokenConstants.TOKEN_EXPIRES_SOON_HEADER, "true")
                }
                else {
                    LOG.debug("Token is still within expiry threshold.")
                }
            }
        }
    }

    private fun tokenExpiresBeforeThreshold(jwtTokenClaims : JwtTokenClaims) : Boolean {
        val expiryDate = jwtTokenClaims.get(EXPIRATION_TIME) as Date
        val expiry = LocalDateTime.ofInstant(expiryDate.toInstant(), ZoneId.systemDefault())
        val minutesUntilExpiry = LocalDateTime.now().until(expiry, MINUTES)
        LOG.debug("Checking token at time {} with expirationTime {} for how many minutes until expiry: {}",
            LocalDateTime.now(), expiry, minutesUntilExpiry)
        if (minutesUntilExpiry <= expiryThresholdInMinutes) {
            LOG.debug("There are {} minutes until expiry which is equal to or less than the configured threshold {}",
                minutesUntilExpiry, expiryThresholdInMinutes)
            return true
        }
        return false
    }

    override fun toString() = ("${javaClass.getSimpleName()} [contextHolder=$contextHolder, expiryThresholdInMinutes=$expiryThresholdInMinutes]")

    companion object {

        private val LOG : Logger = LoggerFactory.getLogger(JwtTokenExpiryFilter::class.java)
    }
}