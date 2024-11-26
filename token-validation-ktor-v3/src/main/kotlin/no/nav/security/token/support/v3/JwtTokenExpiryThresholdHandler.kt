package no.nav.security.token.support.v3

import com.nimbusds.jwt.JWTClaimNames.EXPIRATION_TIME
import io.ktor.server.application.*
import io.ktor.server.response.*
import java.time.LocalDateTime.now
import java.time.LocalDateTime.ofInstant
import java.time.ZoneId.systemDefault
import java.time.temporal.ChronoUnit.MINUTES
import java.util.*
import no.nav.security.token.support.core.JwtTokenConstants.TOKEN_EXPIRES_SOON_HEADER
import no.nav.security.token.support.core.context.TokenValidationContext
import no.nav.security.token.support.core.jwt.JwtTokenClaims
import org.slf4j.LoggerFactory

class JwtTokenExpiryThresholdHandler(private val expiryThreshold: Int) {

    private val log = LoggerFactory.getLogger(JwtTokenExpiryThresholdHandler::class.java.name)

    fun addHeaderOnTokenExpiryThreshold(call: ApplicationCall, ctx: TokenValidationContext) {
        if(expiryThreshold > 0) {
            ctx.issuers.forEach {
                if (tokenExpiresBeforeThreshold(ctx.getClaims(it))) {
                    call.response.header(TOKEN_EXPIRES_SOON_HEADER, "true")
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
        val minutesUntilExpiry = now().until(expiry, MINUTES)
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