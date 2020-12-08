package no.nav.security.token.support.spring.validation.interceptor;

import static org.springframework.core.annotation.AnnotatedElementUtils.findMergedAnnotation;

import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

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

    private static Annotation scanAnnotation(AnnotatedElement a, List<Class<? extends Annotation>> types) {
        return types.stream()
                .map(t -> findMergedAnnotation(a, t))
                .filter(Objects::nonNull)
                .findFirst()
                .orElse(null);
    }
}
