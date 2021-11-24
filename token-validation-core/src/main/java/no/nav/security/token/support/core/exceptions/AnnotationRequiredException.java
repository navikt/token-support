package no.nav.security.token.support.core.exceptions;

import java.lang.reflect.Method;

public class AnnotationRequiredException extends RuntimeException {
    public AnnotationRequiredException(String message) {
        super(message);
    }

    public AnnotationRequiredException(Method method) {
        this("Server misconfigured - controller/method ["
                + method.getDeclaringClass().getName() + "." + method.getName()
                + "] not annotated @Unprotected, @Protected, @RequiredClaims or added to ignore list");
    }
}
