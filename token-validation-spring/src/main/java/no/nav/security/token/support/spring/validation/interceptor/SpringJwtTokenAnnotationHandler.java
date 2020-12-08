package no.nav.security.token.support.spring.validation.interceptor;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import org.springframework.core.annotation.AnnotatedElementUtils;

import no.nav.security.token.support.core.context.TokenValidationContextHolder;
import no.nav.security.token.support.core.validation.JwtTokenAnnotationHandler;

public class SpringJwtTokenAnnotationHandler extends JwtTokenAnnotationHandler {

    public SpringJwtTokenAnnotationHandler(TokenValidationContextHolder tokenValidationContextHolder) {
        super(tokenValidationContextHolder);
    }

    @Override
    protected Annotation getAnnotation(Method method, List<Class<? extends Annotation>> types) {
        return Optional.ofNullable(scanAnnotation(method, types))
                .orElseGet(() -> scanAnnotation(method.getDeclaringClass(), types));
    }

    private static Annotation scanAnnotation(Method m, List<Class<? extends Annotation>> types) {
        return types.stream()
                .map(t -> AnnotatedElementUtils.findMergedAnnotation(m, t))
                .filter(Objects::nonNull)
                .findFirst()
                .orElse(null);
    }

    private static Annotation scanAnnotation(Class<?> clazz, List<Class<? extends Annotation>> types) {
        return types.stream()
                .map(t -> AnnotatedElementUtils.findMergedAnnotation(clazz, t))
                .filter(Objects::nonNull)
                .findFirst()
                .orElse(null);
    }

}
