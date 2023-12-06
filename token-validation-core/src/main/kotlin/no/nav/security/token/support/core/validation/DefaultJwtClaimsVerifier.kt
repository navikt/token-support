package no.nav.security.token.support.core.validation

import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.BadJWTException
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.util.DateUtils
import com.nimbusds.openid.connect.sdk.validators.BadJWTExceptions.IAT_CLAIM_AHEAD_EXCEPTION
import java.util.Date

/**
 * Extends [com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier] with a time check for the issued at ("iat") claim.
 * The claim is only checked if it exists in the given claim set.
 */
class DefaultJwtClaimsVerifier<C : SecurityContext>(acceptedAudience : Set<String?>?, exactMatchClaims : JWTClaimsSet, requiredClaims : Set<String>, prohibitedClaims : Set<String>) : DefaultJWTClaimsVerifier<C>(acceptedAudience, exactMatchClaims, requiredClaims, prohibitedClaims) {

    @Throws(BadJWTException::class)
    override fun verify(claimsSet: JWTClaimsSet, context: C?) {
        super.verify(claimsSet, context)
        claimsSet.issueTime?.let { iat ->
            if (!DateUtils.isBefore(iat, Date(), maxClockSkew.toLong())) {
                throw IAT_CLAIM_AHEAD_EXCEPTION
            }
        }
    }
}