package no.nav.security.token.support.core.exceptions

import java.lang.reflect.Method
import no.nav.security.token.support.core.validation.JwtTokenAnnotationHandler.Companion.SUPPORTED_ANNOTATIONS
class AnnotationRequiredException(message : String) : RuntimeException(message) {
    constructor(method : Method) : this("Server misconfigured - controller/method [${method.declaringClass.name}.${method.name}] not annotated with any of $SUPPORTED_ANNOTATIONS or added to ignore list")
}