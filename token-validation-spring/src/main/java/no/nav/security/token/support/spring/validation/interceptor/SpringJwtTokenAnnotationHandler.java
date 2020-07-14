package no.nav.security.token.support.spring.validation.interceptor;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.AnnotationUtils;

import no.nav.security.token.support.core.context.TokenValidationContextHolder;
import no.nav.security.token.support.core.validation.JwtTokenAnnotationHandler;

public class SpringJwtTokenAnnotationHandler extends JwtTokenAnnotationHandler {

    private static final Logger LOG = LoggerFactory.getLogger(SpringJwtTokenAnnotationHandler.class);

    public SpringJwtTokenAnnotationHandler(TokenValidationContextHolder tokenValidationContextHolder) {
        super(tokenValidationContextHolder);
    }

    @Override
    protected Annotation getAnnotation(Method method, List<Class<? extends Annotation>> types) {
        Annotation annotation = scanAnnotation(method, types);
        if (annotation != null) {
            LOG.debug("Method " + method + " marked @{}", annotation.annotationType());
            return annotation;
        }
        annotation = scanAnnotation(method.getDeclaringClass(), types);
        if (annotation != null) {
            LOG.debug("Method {} marked @{} through annotation on class", method, annotation.annotationType());
            return annotation;
        }
        return null;
    }

    private static Annotation scanAnnotation(Method m, List<Class<? extends Annotation>> types) {
        return types.stream()
                .map(t -> AnnotationUtils.findAnnotation(m, t))
                .filter(Objects::nonNull)
                .findFirst()
                .orElse(null);
    }

    private static Annotation scanAnnotation(Class<?> clazz, List<Class<? extends Annotation>> types) {
        return types.stream()
                .map(t -> AnnotationUtils.findAnnotation(clazz, t))
                .filter(Objects::nonNull)
                .findFirst()
                .orElse(null);
    }

}
