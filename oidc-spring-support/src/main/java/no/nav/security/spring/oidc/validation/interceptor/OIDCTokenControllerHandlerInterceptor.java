package no.nav.security.spring.oidc.validation.interceptor;

import java.lang.reflect.Method;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import no.nav.security.token.support.core.context.JwtTokenClaims;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import no.nav.security.token.support.core.api.Protected;
import no.nav.security.token.support.core.api.ProtectedWithClaims;
import no.nav.security.token.support.core.api.Unprotected;
import no.nav.security.token.support.core.context.JwtTokenValidationContextHolder;
import no.nav.security.token.support.core.context.JwtTokenValidationContext;

public class OIDCTokenControllerHandlerInterceptor implements HandlerInterceptor {

    private final Logger logger = LoggerFactory.getLogger(OIDCTokenControllerHandlerInterceptor.class);
    private final JwtTokenValidationContextHolder contextHolder;
    private String[] ignoreConfig;
    private final Map<Object, Boolean> handlerFlags = new ConcurrentHashMap<>();

    public OIDCTokenControllerHandlerInterceptor(AnnotationAttributes enableOIDCTokenValidation,
            JwtTokenValidationContextHolder contextHolder) {
        this.contextHolder = contextHolder;

        if (enableOIDCTokenValidation != null) {
            ignoreConfig = enableOIDCTokenValidation.getStringArray("ignore");
            if (ignoreConfig == null) {
                ignoreConfig = new String[0];
            }
        }
        else {
            // nothing explicitly configured to be ignored, intercept everything
            ignoreConfig = new String[0];
        }
    }

    @Override
    public void afterCompletion(HttpServletRequest arg0, HttpServletResponse arg1, Object handler, Exception arg3) {
    }

    @Override
    public void postHandle(HttpServletRequest arg0, HttpServletResponse arg1, Object handler, ModelAndView arg3) {

    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        JwtTokenValidationContext validationContext = contextHolder
                .getOIDCValidationContext();

        if (handler instanceof HandlerMethod) {
            HandlerMethod handlerMethod = (HandlerMethod) handler;
            if (shouldIgnore(handlerMethod.getBean())) {
                return true;
            }
            Unprotected unprotectedAnnotation = handlerMethod.getMethodAnnotation(Unprotected.class);
            if (unprotectedAnnotation != null) {
                logger.debug("method " + handlerMethod + " marked @Unprotected");
                return true;
            }
            ProtectedWithClaims withClaimsAnnotation = handlerMethod.getMethodAnnotation(ProtectedWithClaims.class);
            if (withClaimsAnnotation != null) {
                logger.debug("method " + handlerMethod + " marked @ProtectedWithClaims");
                return handleProtectedWithClaimsAnnotation(validationContext, withClaimsAnnotation);
            }
            else {
                Protected protectedAnnotation = handlerMethod.getMethodAnnotation(Protected.class);
                if (protectedAnnotation != null) {
                    logger.debug("method " + handlerMethod + " marked @Protected");
                    return handleProtectedAnnotation(validationContext);
                }
            }

            Method method = handlerMethod.getMethod();
            Class<?> declaringClass = method.getDeclaringClass();
            if (declaringClass.isAnnotationPresent(Unprotected.class)) {
                logger.debug("method " + handlerMethod + " marked @Unprotected throug annotation on class");
                return true;
            }

            if (declaringClass.isAnnotationPresent(ProtectedWithClaims.class)) {
                logger.debug("method " + handlerMethod + " marked @ProtectedWithClaims");
                return handleProtectedWithClaimsAnnotation(validationContext,
                        declaringClass.getAnnotation(ProtectedWithClaims.class));
            }
            else {
                if (declaringClass.isAnnotationPresent(Protected.class)) {
                    logger.debug("method " + handlerMethod + " marked @Protected");
                    return handleProtectedAnnotation(validationContext);
                }
            }
            logger.debug("method " + handlerMethod + " not marked, access denied (returning NOT_IMPLEMENTED)");
            throw new OIDCUnauthorizedException("Server misconfigured - controller/method ["
                    + handlerMethod.getBean().getClass().getName() + "." + handlerMethod.getMethod().getName()
                    + "] not annotated @Unprotected, @Protected or added to ignore list");

        }
        logger.debug("Handler is of type {}, allowing unprotected access to the resources it accesses",
                handler.getClass().getSimpleName());
        return true;
    }

    protected boolean handleProtectedAnnotation(JwtTokenValidationContext validationContext) {
        if (validationContext.hasValidToken()) {
            return true;
        }
        logger.debug("no token found in validation context");
        throw new OIDCUnauthorizedException("Authorization token required");
    }

    protected boolean handleProtectedWithClaimsAnnotation(JwtTokenValidationContext validationContext,
                                                          ProtectedWithClaims annotation) {
        String issuer = annotation.issuer();
        String[] claims = annotation.claimMap();
        if (StringUtils.isNotBlank(issuer)) {
            JwtTokenClaims tokenClaims = validationContext.getClaims(issuer);
            if (tokenClaims == null) {
                logger.trace(String.format(
                        "could not find token for issuer '%s' in validation context. Login may be required.",
                        issuer));
                throw new OIDCUnauthorizedException("Authorization token not authorized");
            }
            if (!containsRequiredClaims(tokenClaims, annotation.combineWithOr(), annotation.claimMap())) {
                logger.info("token does not contain all annotated claims");
                throw new OIDCUnauthorizedException("Authorization token not authorized");
            }
        }
        return true;
    }

    protected boolean containsRequiredClaims(JwtTokenClaims tokenClaims, boolean combineWithOr, String... claims) {
        logger.debug("choose matching logic based on combineWithOr=" + combineWithOr);
        return combineWithOr ? containsAnyClaim(tokenClaims, claims)
                : containsAllClaims(tokenClaims, claims);
    }

    protected boolean containsAllClaims(JwtTokenClaims tokenClaims, String... claims) {
        for (String string : claims) {
            String name = StringUtils.substringBefore(string, "=").trim();
            String value = StringUtils.substringAfter(string, "=").trim();
            if (StringUtils.isNotBlank(name)) {
                if (!tokenClaims.containsClaim(name, value)) {
                    logger.debug(String.format("token does not contain %s = %s", name, value));
                    return false;
                }
            }
        }
        return true;
    }

    protected boolean containsAnyClaim(JwtTokenClaims tokenClaims, String... claims) {
        if (claims != null && claims.length > 0) {
            for (String string : claims) {
                String name = StringUtils.substringBefore(string, "=").trim();
                String value = StringUtils.substringAfter(string, "=").trim();
                if (StringUtils.isNotBlank(name)) {
                    if (tokenClaims.containsClaim(name, value)) {
                        return true;
                    }
                }
            }
            logger.debug("token does not contain any of the listed claims");
            return false;
        }
        logger.debug("no claims listed, so claim checking is ok.");
        return true;
    }

    private boolean shouldIgnore(Object object) {
        Boolean flag = handlerFlags.get(object);
        if (flag != null) {
            return flag;
        }
        String fullName = object.getClass().getName();
        for (String ignore : ignoreConfig) {
            if (fullName.startsWith(ignore)) {
                logger.info("Adding " + fullName + " to OIDC validation ignore list");
                handlerFlags.put(object, true);
                return true;
            }
        }
        logger.info("Adding " + fullName + " to OIDC validation interceptor list");
        handlerFlags.put(object, false);
        return false;
    }
}
