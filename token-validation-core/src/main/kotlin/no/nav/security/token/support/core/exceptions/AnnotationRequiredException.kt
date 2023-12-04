package no.nav.security.token.support.core.exceptions

import java.lang.reflect.Method

class AnnotationRequiredException(message : String?) : RuntimeException(message) {
    constructor(method : Method) : this("Server misconfigured - controller/method ["
        + method.declaringClass.name + "." + method.name
        + "] not annotated @Unprotected, @Protected, @RequiredClaims or added to ignore list")
}