package no.nav.security.token.support.ktor

import io.ktor.application.ApplicationCall
import io.ktor.response.header
import no.nav.security.token.support.core.JwtTokenConstants
import no.nav.security.token.support.core.context.TokenValidationContext
import no.nav.security.token.support.core.jwt.JwtTokenClaims
import org.slf4j.LoggerFactory
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.temporal.ChronoUnit
import java.util.*

class JwtTokenExpiryThresholdHandler(private val expiryThreshold: Int) {

    private val log = LoggerFactory.getLogger(JwtTokenExpiryThresholdHandler::class.java.name)

    fun addHeaderOnTokenExpiryThreshold(call: ApplicationCall, tokenValidationContext: TokenValidationContext) {
        if(expiryThreshold > 0) {
            for (issuer in tokenValidationContext.issuers) {
                val jwtTokenClaims = tokenValidationContext.getClaims(issuer)
                if (tokenExpiresBeforeThreshold(jwtTokenClaims)) {
                    call.response.header(JwtTokenConstants.TOKEN_EXPIRES_SOON_HEADER, "true")
                } else {
                    log.debug("Token is still within expiry threshold.")
                }
            }
        } else {
            log.debug("Expiry threshold is not set")
        }
    }

    private fun tokenExpiresBeforeThreshold(jwtTokenClaims: JwtTokenClaims): Boolean {
        val expiryDate = jwtTokenClaims["exp"] as Date
        val expiry = LocalDateTime.ofInstant(expiryDate.toInstant(), ZoneId.systemDefault())
        val minutesUntilExpiry = LocalDateTime.now().until(expiry, ChronoUnit.MINUTES)
        log.debug("Checking token at time {} with expirationTime {} for how many minutes until expiry: {}",
            LocalDateTime.now(), expiry, minutesUntilExpiry)
        if (minutesUntilExpiry <= expiryThreshold) {
            log.debug("There are {} minutes until expiry which is equal to or less than the configured threshold {}",
                minutesUntilExpiry, expiryThreshold)
            return true
        }
        return false
    }
}
