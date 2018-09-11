package no.nav.security.spring.oidc.validation.interceptor;

import java.lang.reflect.Method;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import no.nav.security.oidc.OIDCConstants;
import no.nav.security.oidc.api.Protected;
import no.nav.security.oidc.api.ProtectedWithClaims;
import no.nav.security.oidc.api.Unprotected;
import no.nav.security.oidc.context.OIDCClaims;
import no.nav.security.oidc.context.OIDCRequestContextHolder;
import no.nav.security.oidc.context.OIDCValidationContext;

public class OIDCTokenControllerHandlerInterceptor implements HandlerInterceptor {

    private Logger logger = LoggerFactory.getLogger(OIDCTokenControllerHandlerInterceptor.class);
    private OIDCRequestContextHolder contextHolder;
    private String[] ignoreConfig;
    private Map<Object, Boolean> handlerFlags = new ConcurrentHashMap<>();

    public OIDCTokenControllerHandlerInterceptor(AnnotationAttributes enableOIDCTokenValidation,
            OIDCRequestContextHolder contextHolder) {
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
    public void afterCompletion(HttpServletRequest arg0, HttpServletResponse arg1, Object handler, Exception arg3)
            throws Exception {
    }

    @Override
    public void postHandle(HttpServletRequest arg0, HttpServletResponse arg1, Object handler, ModelAndView arg3)
            throws Exception {

    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        OIDCValidationContext validationContext = (OIDCValidationContext) contextHolder
                .getRequestAttribute(OIDCConstants.OIDC_VALIDATION_CONTEXT);

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
        logger.info("Handler is of type {}, allowing unprotected access to the resources it accesses",
                handler.getClass().getSimpleName());
        return true;
    }

    protected boolean handleProtectedAnnotation(OIDCValidationContext validationContext) {
        if (validationContext.hasValidToken()) {
            return true;
        }
        logger.info("no token found in validation context");
        throw new OIDCUnauthorizedException("Authorization token required");
    }

    protected boolean handleProtectedWithClaimsAnnotation(OIDCValidationContext validationContext,
            ProtectedWithClaims annotation) {
        String issuer = annotation.issuer();
        String[] claims = annotation.claimMap();
        if (StringUtils.isNotBlank(issuer)) {
            OIDCClaims tokenClaims = validationContext.getClaims(issuer);
            if (tokenClaims == null) {
                logger.trace(String.format(
                        "could not find token for issuer '%s' in validation context. Login may be required.",
                        issuer));
                throw new OIDCUnauthorizedException("Authorization token not authorized");
            }
            if (!containsRequiredClaims(tokenClaims, claims)) {
                logger.info("token does not contain all annotated claims");
                throw new OIDCUnauthorizedException("Authorization token not authorized");
            }
        }
        return true;
    }

    protected boolean containsRequiredClaims(OIDCClaims tokenClaims, String... claims) {
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
