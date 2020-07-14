package no.nav.security.token.support.spring.validation.interceptor;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.http.HttpStatus;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import no.nav.security.token.support.core.exceptions.AnnotationRequiredException;
import no.nav.security.token.support.core.validation.JwtTokenAnnotationHandler;

public class JwtTokenHandlerInterceptor extends HandlerInterceptorAdapter {

    private final Logger logger = LoggerFactory.getLogger(JwtTokenHandlerInterceptor.class);
    private final JwtTokenAnnotationHandler jwtTokenAnnotationHandler;
    private String[] ignoreConfig;
    private final Map<Object, Boolean> handlerFlags = new ConcurrentHashMap<>();

    public JwtTokenHandlerInterceptor(AnnotationAttributes enableJwtTokenValidation,
            JwtTokenAnnotationHandler jwtTokenAnnotationHandler) {
        this.jwtTokenAnnotationHandler = jwtTokenAnnotationHandler;

        if (enableJwtTokenValidation != null) {
            ignoreConfig = enableJwtTokenValidation.getStringArray("ignore");
            if (ignoreConfig == null) {
                ignoreConfig = new String[0];
            }
        } else {
            // nothing explicitly configured to be ignored, intercept everything
            ignoreConfig = new String[0];
        }
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (handler instanceof HandlerMethod) {
            HandlerMethod handlerMethod = (HandlerMethod) handler;
            if (shouldIgnore(handlerMethod.getBean())) {
                return true;
            }
            try {
                return jwtTokenAnnotationHandler.assertValidAnnotation(handlerMethod.getMethod());
            } catch (AnnotationRequiredException e) {
                logger.error("received AnnotationRequiredException from JwtTokenAnnotationHandler. return " +
                        "status={}", HttpStatus.NOT_IMPLEMENTED, e);
                throw new ResponseStatusException(HttpStatus.NOT_IMPLEMENTED, "endpoint not accessible", e);
            } catch (Exception e) {
                throw new JwtTokenUnauthorizedException(e);
            }
        }
        logger.debug("Handler is of type {}, allowing unprotected access to the resources it accesses",
                handler.getClass().getSimpleName());
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
