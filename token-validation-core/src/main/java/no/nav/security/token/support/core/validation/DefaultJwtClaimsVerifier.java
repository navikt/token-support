package no.nav.security.token.support.core.validation;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.openid.connect.sdk.validators.BadJWTExceptions;

import java.util.Date;
import java.util.Set;

/**
 * Extends {@link com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier} with a time check for the issued at ("iat") claim.
 * The claim is only checked if it exists in the given claim set.
 */
public class DefaultJwtClaimsVerifier<C extends SecurityContext> extends DefaultJWTClaimsVerifier<C> {

    public DefaultJwtClaimsVerifier(final Set<String> acceptedAudience,
                                    final JWTClaimsSet exactMatchClaims,
                                    final Set<String> requiredClaims,
                                    final Set<String> prohibitedClaims) {
        super(acceptedAudience, exactMatchClaims, requiredClaims, prohibitedClaims);
    }

    @Override
    public void verify(final JWTClaimsSet claimsSet, final C context) throws BadJWTException {
        super.verify(claimsSet, context);

        Date iat = claimsSet.getIssueTime();
        if (iat != null) {
            Date now = new Date();
            if (!iat.equals(now) && !DateUtils.isBefore(iat, now, super.getMaxClockSkew())) {
                throw BadJWTExceptions.IAT_CLAIM_AHEAD_EXCEPTION;
            }
        }
    }
}
