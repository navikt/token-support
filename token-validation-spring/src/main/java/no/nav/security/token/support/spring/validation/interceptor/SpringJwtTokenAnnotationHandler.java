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

public final class SpringJwtTokenAnnotationHandler extends JwtTokenAnnotationHandler {

    public SpringJwtTokenAnnotationHandler(TokenValidationContextHolder holder) {
        super(holder);
    }

    @Override
    protected Annotation getAnnotation(Method m, List<Class<? extends Annotation>> types) {
        return Optional.ofNullable(findAnnotation(m, types))
                .orElseGet(() -> findAnnotation(m.getDeclaringClass(), types));
    }

    private static Annotation findAnnotation(AnnotatedElement e, List<Class<? extends Annotation>> types) {
        return types.stream()
                .map(t -> findMergedAnnotation(e, t))
                .filter(Objects::nonNull)
                .findFirst()
                .orElse(null);
    }
}
