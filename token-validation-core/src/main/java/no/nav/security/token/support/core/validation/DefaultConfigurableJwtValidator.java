package no.nav.security.token.support.core.validation;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import no.nav.security.token.support.core.exceptions.JwtTokenValidatorException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The default configurable JwtTokenValidator.
 * Configures sane defaults and delegates verification to {@link DefaultJwtClaimsVerifier}:
 *
 * <p>The following set of claims are required by default and <i>must</i>be present in the JWTs:</p>
 * <ul>
 *     <li>iss - Issuer</li>
 *     <li>sub - Subject</li>
 *     <li>aud - Audience</li>
 *     <li>exp - Expiration Time</li>
 *     <li>iat - Issued At</li>
 * </ul>
 *
 * <p>Otherwise, the following checks are in place:</p>
 * <ul>
 *     <li>The issuer ("iss") claim value must match exactly with the specified accepted issuer value.</li>
 *     <li><i>At least one</i> of the values in audience ("aud") claim must match one of the specified accepted audiences.</li>
 *     <li>Time validity checks are performed on the issued at ("iat"), expiration ("exp") and not-before ("nbf") claims if and only if they are present.</li>
 * </ul>
 *
 * <p>Note: the not-before ("nbf") claim is <i>not</i> a required claim. Conversely, the expiration ("exp") claim <i>is</i> a default required claim.</p>
 *
 * <p>Specifying optional claims will <i>remove</i> any matching claims from the default set of required claims.</p>
 *
 * <p>Audience validation is only skipped if the claim is explicitly configured as an optional claim, and the list of accepted audiences is empty / not configured.
 *
 * <p>If the audience claim is explicitly configured as an optional claim and the list of accepted audience is non-empty, the following rules apply:
 * <ul>
 *     <li>If the audience claim is present (non-empty) in the JWT, it will be matched against the list of accepted audiences.</li>
 *     <li>If the audience claim is not present, the audience match and existence checks are skipped - since it is an optional claim.</li>
 * </ul>
 *
 * <p>An <i>empty</i> list of accepted audiences alone does <i>not</i> remove the audience ("aud") claim from the default set of required claims; the claim must explicitly be specified as optional.</p>
 */
public class DefaultConfigurableJwtValidator implements JwtTokenValidator {
    private static final List<String> DEFAULT_REQUIRED_CLAIMS = List.of(
        JWTClaimNames.AUDIENCE,
        JWTClaimNames.EXPIRATION_TIME,
        JWTClaimNames.ISSUED_AT,
        JWTClaimNames.ISSUER,
        JWTClaimNames.SUBJECT
    );
    private static final Set<String> PROHIBITED_CLAIMS = Collections.emptySet();
    private final JWKSource<SecurityContext> jwkSource;
    private final ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

    public DefaultConfigurableJwtValidator(String issuer, List<String> acceptedAudiences, JWKSource<SecurityContext> jwkSource) {
        this(issuer, acceptedAudiences, null, jwkSource);
    }

    public DefaultConfigurableJwtValidator(String issuer, List<String> acceptedAudiences, List<String> optionalClaims, JWKSource<SecurityContext> jwkSource) {
        acceptedAudiences = Optional.ofNullable(acceptedAudiences).orElse(List.of());
        optionalClaims = Optional.ofNullable(optionalClaims).orElse(List.of());

        var requiredClaims = difference(DEFAULT_REQUIRED_CLAIMS, optionalClaims);
        var exactMatchClaims = new JWTClaimsSet.Builder()
            .issuer(issuer)
            .build();
        var keySelector = new JWSVerificationKeySelector<>(
            JWSAlgorithm.RS256,
            jwkSource
        );
        var claimsVerifier = new DefaultJwtClaimsVerifier<>(
            acceptedAudiences(acceptedAudiences, optionalClaims),
            exactMatchClaims,
            requiredClaims,
            PROHIBITED_CLAIMS
        );

        var jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWSKeySelector(keySelector);
        jwtProcessor.setJWTClaimsSetVerifier(claimsVerifier);

        this.jwkSource = jwkSource;
        this.jwtProcessor = jwtProcessor;
    }

    @Override
    public void assertValidToken(String tokenString) throws JwtTokenValidatorException {
        try {
            jwtProcessor.process(tokenString, null);
        } catch (Throwable t) {
            throw new JwtTokenValidatorException("Token validation failed: " + t.getMessage(), t);
        }
    }

    private static Set<String> acceptedAudiences(List<String> acceptedAudiences, List<String> optionalClaims) {
        if (!optionalClaims.contains(JWTClaimNames.AUDIENCE)) {
            return new HashSet<>(acceptedAudiences);
        }

        if (acceptedAudiences.isEmpty()) {
            // Effectively skips all audience existence and matching checks
            return null;
        }

        // Otherwise, add null to instruct DefaultJwtClaimsVerifier to validate against audience if present in the JWT,
        // but don't require existence of the claim for all JWTs.
        var acceptedAudiencesCopy = new ArrayList<>(acceptedAudiences);
        acceptedAudiencesCopy.add(null);
        return new HashSet<>(acceptedAudiencesCopy);
    }

    private static <T> Set<T> difference(List<T> first, List<T> second) {
        return first.stream()
            .filter(c -> !second.contains(c))
            .collect(Collectors.toUnmodifiableSet());
    }

    protected JWKSource<SecurityContext> getJwkSource() {
        return this.jwkSource;
    }
}
