package no.nav.security.token.support.core.validation;

import no.nav.security.token.support.core.api.Protected;
import no.nav.security.token.support.core.api.ProtectedWithClaims;
import no.nav.security.token.support.core.api.RequiredIssuers;
import no.nav.security.token.support.core.api.Unprotected;
import no.nav.security.token.support.core.context.TokenValidationContextHolder;
import no.nav.security.token.support.core.exceptions.AnnotationRequiredException;
import no.nav.security.token.support.core.exceptions.JwtTokenInvalidClaimException;
import no.nav.security.token.support.core.exceptions.JwtTokenMissingException;
import no.nav.security.token.support.core.jwt.JwtToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static no.nav.security.token.support.core.utils.Cluster.*;
import static no.nav.security.token.support.core.utils.JwtTokenUtil.contextHasValidToken;
import static no.nav.security.token.support.core.utils.JwtTokenUtil.getJwtToken;

public class JwtTokenAnnotationHandler {

    private static final List<Class<? extends Annotation>> SUPPORTED_ANNOTATIONS = List.of(RequiredIssuers.class, ProtectedWithClaims.class,
            Protected.class, Unprotected.class);
    protected static final Logger LOG = LoggerFactory.getLogger(JwtTokenAnnotationHandler.class);
    private final TokenValidationContextHolder tokenValidationContextHolder;

    public JwtTokenAnnotationHandler(TokenValidationContextHolder tokenValidationContextHolder) {
        this.tokenValidationContextHolder = tokenValidationContextHolder;
    }

    public boolean assertValidAnnotation(Method m) throws AnnotationRequiredException {
        return Optional.ofNullable(getAnnotation(m, SUPPORTED_ANNOTATIONS))
                .map(this::assertValidAnnotation)
                .orElseThrow(() -> new AnnotationRequiredException(m));
    }

    private boolean assertValidAnnotation(Annotation a) {
        if (a instanceof Unprotected) {
            LOG.debug("annotation is of type={}, no token validation performed.", Unprotected.class.getSimpleName());
            return true;
        }
        if (a instanceof RequiredIssuers r) {
            return handleRequiredIssuers(r);
        }
        if (a instanceof ProtectedWithClaims p) {
            return handleProtectedWithClaims(p);
        }
        if (a instanceof Protected) {
            return handleProtected();
        }
        LOG.debug("Annotation is unknown,  type={}, no token validation performed. but possible bug so throw exception", a.annotationType());
        return false;
    }

    private boolean handleProtected() {
        LOG.debug("Annotation is of type={}, check if context has valid token.", Protected.class.getSimpleName());
        if (contextHasValidToken(tokenValidationContextHolder)) {
            return true;
        }
        throw new JwtTokenMissingException();
    }

    private boolean handleProtectedWithClaims(ProtectedWithClaims a) {
        if (!isProd() && Arrays.stream(a.excludedClusters()).toList().contains(currentCluster())) {
            LOG.info("Excluding current cluster {} from validation", currentCluster());
            return true;
        }
        LOG.debug("Annotation is of type={}, do token validation and claim checking.", ProtectedWithClaims.class.getSimpleName());
        var jwtToken = getJwtToken(a.issuer(), tokenValidationContextHolder);
        if (jwtToken.isEmpty()) {
            throw new JwtTokenMissingException();
        }

        if (!handleProtectedWithClaimsAnnotation(a, jwtToken.get())) {
            throw new JwtTokenInvalidClaimException(a);
        }
        return true;
    }

    private boolean handleRequiredIssuers(RequiredIssuers a) {
        boolean hasToken = false;
        for (var sub : a.value()) {
            var jwtToken = getJwtToken(sub.issuer(), tokenValidationContextHolder);
            if (jwtToken.isEmpty()) {
                continue;
            }
            if (handleProtectedWithClaimsAnnotation(sub, jwtToken.get())) {
                return true;
            }
            hasToken = true;
        }
        if (!hasToken) {
            throw new JwtTokenMissingException(a);
        }
        throw new JwtTokenInvalidClaimException(a);
    }

    protected Annotation getAnnotation(Method method, List<Class<? extends Annotation>> types) {
        return Optional.ofNullable(findAnnotation(types, method.getAnnotations()))
                .orElseGet(() -> findAnnotation(types, method.getDeclaringClass().getAnnotations()));
    }

    private static Annotation findAnnotation(List<Class<? extends Annotation>> types, Annotation... annotations) {
        return Arrays.stream(annotations)
                .filter(a -> types.contains(a.annotationType()))
                .findFirst()
                .orElse(null);
    }

    protected boolean handleProtectedWithClaimsAnnotation(ProtectedWithClaims a, JwtToken jwtToken) {
        return handleProtectedWithClaims(a.issuer(), a.claimMap(), a.combineWithOr(), jwtToken);
    }

    protected boolean handleProtectedWithClaims(String issuer, String[] requiredClaims, boolean combineWithOr, JwtToken jwtToken) {
        if (Objects.nonNull(issuer) && !issuer.isEmpty()) {
            return containsRequiredClaims(jwtToken, combineWithOr, requiredClaims);
        }
        return true;
    }

    protected boolean containsRequiredClaims(JwtToken jwtToken, boolean combineWithOr, String... claims) {
        LOG.debug("choose matching logic based on combineWithOr={}",combineWithOr);
        return combineWithOr ? containsAnyClaim(jwtToken, claims)
                : containsAllClaims(jwtToken, claims);
    }

    private boolean containsAllClaims(JwtToken jwtToken, String... claims) {
        if (claims != null && claims.length > 0) {
            return Arrays.stream(claims)
                    .map(claimUnparsed -> claimUnparsed.split("="))
                    .filter(pair -> pair.length == 2)
                    .allMatch(pair -> jwtToken.containsClaim(pair[0].trim(), pair[1].trim()));
        }
        return true;
    }

    private boolean containsAnyClaim(JwtToken jwtToken, String... claims) {
        if (claims != null && claims.length > 0) {
            return Arrays.stream(claims)
                    .map(claimUnparsed -> claimUnparsed.split("="))
                    .filter(pair -> pair.length == 2)
                    .anyMatch(pair -> jwtToken.containsClaim(pair[0].trim(), pair[1].trim()));
        }
        LOG.debug("no claims listed, so claim checking is ok.");
        return true;
    }
}