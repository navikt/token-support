package no.nav.security.token.support.core.validation;

import static no.nav.security.token.support.core.utils.JwtTokenUtil.contextHasValidToken;
import static no.nav.security.token.support.core.utils.JwtTokenUtil.getJwtToken;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import no.nav.security.token.support.core.api.Protected;
import no.nav.security.token.support.core.api.ProtectedWithClaims;
import no.nav.security.token.support.core.api.Protection;
import no.nav.security.token.support.core.api.Unprotected;
import no.nav.security.token.support.core.context.TokenValidationContextHolder;
import no.nav.security.token.support.core.exceptions.AnnotationRequiredException;
import no.nav.security.token.support.core.exceptions.JwtTokenInvalidClaimException;
import no.nav.security.token.support.core.exceptions.JwtTokenMissingException;
import no.nav.security.token.support.core.jwt.JwtToken;

public class JwtTokenAnnotationHandler {

    private static final Logger log = LoggerFactory.getLogger(JwtTokenAnnotationHandler.class);
    private final TokenValidationContextHolder tokenValidationContextHolder;

    public JwtTokenAnnotationHandler(TokenValidationContextHolder tokenValidationContextHolder) {
        this.tokenValidationContextHolder = tokenValidationContextHolder;
    }

    public boolean assertValidAnnotation(Method method) throws AnnotationRequiredException {
        Annotation annotation = getAnnotation(method,
                List.of(Protection.class, ProtectedWithClaims.class, Protected.class, Unprotected.class));
        if (annotation == null) {
            throw new AnnotationRequiredException("Server misconfigured - controller/method ["
                    + method.getClass().getName() + "." + method.getName()
                    + "] not annotated @Unprotected, @Protected or added to ignore list");
        }
        return assertValidAnnotation(annotation);
    }

    private boolean assertValidAnnotation(Annotation annotation) {
        if (annotation instanceof Unprotected) {
            log.debug("annotation is of type={}, no token validation performed.", Unprotected.class.getSimpleName());
            return true;
        }
        if (annotation instanceof Protection) {
            boolean hasToken = false;
            var ann = Protection.class.cast(annotation);
            for (var sub : ann.value()) {
                var jwtToken = getJwtToken(sub.issuer(), tokenValidationContextHolder);
                if (jwtToken.isEmpty()) {
                    continue;
                }
                hasToken = true;
                if (handleProtectedWithClaimsAnnotation(sub, jwtToken.get())) {
                    return true;
                }
            }
            if (!hasToken) {
                throw new JwtTokenMissingException("no valid token found in validation context for any of the issuers " + issuers(ann));
            }
            throw new JwtTokenInvalidClaimException("required claims not present in token for any of " + issuersAndClaims(ann));
        }
        if (annotation instanceof ProtectedWithClaims) {
            log.debug("annotation is of type={}, do token validation and claim checking.", ProtectedWithClaims.class.getSimpleName());
            var ann = ProtectedWithClaims.class.cast(annotation);
            var jwtToken = getJwtToken(ann.issuer(), tokenValidationContextHolder);
            if (jwtToken.isEmpty()) {
                throw new JwtTokenMissingException("no valid token found in validation context");
            }
            if (!handleProtectedWithClaimsAnnotation(ann, jwtToken.get())) {
                throw new JwtTokenInvalidClaimException("required claims not present in token." + Arrays.asList(ann.claimMap()));
            }
            return true;
        }
        if (annotation instanceof Protected) {
            log.debug("annotation is of type={}, check if context has valid token.", Protected.class.getSimpleName());
            if (contextHasValidToken(tokenValidationContextHolder)) {
                return true;
            }
            throw new JwtTokenMissingException("no valid token found in validation context");

        }
        log.debug("annotation is unknown,  type={}, no token validation performed. but possible bug so throw exception", annotation.annotationType());
        return false;

    }

    private static Map<String, String[]> issuersAndClaims(Protection ann) {
        return Arrays.stream(ann.value())
                .collect(Collectors.toMap(ProtectedWithClaims::issuer, ProtectedWithClaims::claimMap));
    }

    private static List<String> issuers(Protection ann) {
        return Arrays.stream(ann.value()).map(ProtectedWithClaims::issuer).collect(Collectors.toList());
    }

    protected Annotation getAnnotation(Method method, List<Class<? extends Annotation>> types) {
        Annotation annotation = findAnnotation(method.getAnnotations(), types);
        if (annotation != null) {
            log.debug("method " + method + " marked @{}", annotation.annotationType());
            return annotation;
        }
        Class<?> declaringClass = method.getDeclaringClass();
        annotation = findAnnotation(declaringClass.getAnnotations(), types);
        if (annotation != null) {
            log.debug("method {} marked @{} through annotation on class", method, annotation.annotationType());
            return annotation;
        }
        return null;
    }

    private static Annotation findAnnotation(Annotation[] annotations, List<Class<? extends Annotation>> types) {
        return annotations != null ? Arrays.stream(annotations)
                .filter(a -> types.contains(a.annotationType()))
                .findFirst()
                .orElse(null) : null;
    }

    protected boolean handleProtectedWithClaimsAnnotation(ProtectedWithClaims annotation, JwtToken jwtToken) {
        return handleProtectedWithClaims(annotation.issuer(), annotation.claimMap(), annotation.combineWithOr(), jwtToken);
    }

    protected boolean handleProtectedWithClaims(String issuer, String[] requiredClaims, boolean combineWithOr, JwtToken jwtToken) {
        if (Objects.nonNull(issuer) && issuer.length() > 0) {
            if (!containsRequiredClaims(jwtToken, combineWithOr, requiredClaims)) {
                return false;
            }
        }
        return true;
    }

    protected boolean containsRequiredClaims(JwtToken jwtBearerToken, boolean combineWithOr, String... claims) {
        log.debug("choose matching logic based on combineWithOr=" + combineWithOr);
        return combineWithOr ? containsAnyClaim(jwtBearerToken, claims)
                : containsAllClaims(jwtBearerToken, claims);
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
        log.debug("no claims listed, so claim checking is ok.");
        return true;
    }

}
