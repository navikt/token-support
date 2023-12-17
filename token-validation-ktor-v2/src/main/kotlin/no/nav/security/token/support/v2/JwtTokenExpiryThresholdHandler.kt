package no.nav.security.token.support.v2

import com.nimbusds.jwt.JWTClaimNames.EXPIRATION_TIME
import io.ktor.server.application.ApplicationCall
import io.ktor.server.response.header
import java.time.LocalDateTime
import java.time.LocalDateTime.*
import java.time.ZoneId
import java.time.ZoneId.*
import java.time.temporal.ChronoUnit
import java.util.Date
import org.slf4j.LoggerFactory
import no.nav.security.token.support.core.JwtTokenConstants
import no.nav.security.token.support.core.context.TokenValidationContext
import no.nav.security.token.support.core.jwt.JwtTokenClaims

class JwtTokenExpiryThresholdHandler(private val expiryThreshold: Int) {

    private val log = LoggerFactory.getLogger(JwtTokenExpiryThresholdHandler::class.java.name)

    fun addHeaderOnTokenExpiryThreshold(call: ApplicationCall, tokenValidationContext: TokenValidationContext) {
        if(expiryThreshold > 0) {
            tokenValidationContext.issuers.forEach { issuer ->
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
        val expiryDate = jwtTokenClaims.get(EXPIRATION_TIME) as Date
        val expiry = ofInstant(expiryDate.toInstant(), systemDefault())
        val minutesUntilExpiry = now().until(expiry, ChronoUnit.MINUTES)
        log.debug("Checking token at time {} with expirationTime {} for how many minutes until expiry: {}",
            now(), expiry, minutesUntilExpiry)
        if (minutesUntilExpiry <= expiryThreshold) {
            log.debug("There are {} minutes until expiry which is equal to or less than the configured threshold {}",
                minutesUntilExpiry, expiryThreshold)
            return true
        }
        return false
    }
}