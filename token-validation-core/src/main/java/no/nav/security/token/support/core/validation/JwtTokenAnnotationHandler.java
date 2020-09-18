package no.nav.security.token.support.core.validation;

import no.nav.security.token.support.core.api.Protected;
import no.nav.security.token.support.core.api.ProtectedWithClaims;
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
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import static no.nav.security.token.support.core.utils.JwtTokenUtil.contextHasValidToken;
import static no.nav.security.token.support.core.utils.JwtTokenUtil.getJwtToken;

public class JwtTokenAnnotationHandler {

    private static final Logger log = LoggerFactory.getLogger(JwtTokenAnnotationHandler.class);
    private final TokenValidationContextHolder tokenValidationContextHolder;

    public JwtTokenAnnotationHandler(TokenValidationContextHolder tokenValidationContextHolder) {
        this.tokenValidationContextHolder = tokenValidationContextHolder;
    }

    public boolean assertValidAnnotation(Method method) throws AnnotationRequiredException {
        Annotation annotation = getAnnotation(method, Arrays.asList(ProtectedWithClaims.class, Protected.class, Unprotected.class));
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
        } else if (annotation instanceof ProtectedWithClaims) {
            log.debug("annotation is of type={}, do token validation and claim checking.", ProtectedWithClaims.class.getSimpleName());
            return handleProtectedWithClaimsAnnotation((ProtectedWithClaims) annotation);
        } else if (annotation instanceof Protected) {
            log.debug("annotation is of type={}, check if context has valid token.", Protected.class.getSimpleName());
            if (contextHasValidToken(tokenValidationContextHolder)){
                return true;
            } else {
                throw new JwtTokenMissingException("no valid token found in validation context");
            }

        } else {
            log.debug("annotation is unknown,  type={}, no token validation performed. but possible bug so throw exception", annotation.annotationType());
            return false;
        }
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

    private static Annotation findAnnotation(Annotation[] annotations, List<Class<? extends Annotation>> types){
        return annotations != null ?
            Arrays.stream(annotations)
                .filter(a -> types.contains(a.annotationType()))
                .findFirst()
                .orElse(null) : null;
    }

    protected boolean handleProtectedWithClaimsAnnotation(ProtectedWithClaims annotation) {
        return handleProtectedWithClaims(annotation.issuer(), annotation.claimMap(), annotation.combineWithOr());
    }

    protected boolean handleProtectedWithClaims(String issuer, String[] requiredClaims, boolean combineWithOr) {
        if (Objects.nonNull(issuer) && issuer.length() > 0) {

            JwtToken jwtToken = getJwtToken(issuer, tokenValidationContextHolder)
                .orElseThrow(() -> new JwtTokenMissingException("no valid token found in validation context"));
            if (!containsRequiredClaims(jwtToken, combineWithOr, requiredClaims)) {
                throw new JwtTokenInvalidClaimException("required claims not present in token." + Arrays.asList(requiredClaims));
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
