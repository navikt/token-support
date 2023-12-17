package no.nav.security.token.support.spring.validation.interceptor

import kotlin.annotation.AnnotationRetention.RUNTIME
import kotlin.annotation.AnnotationTarget.ANNOTATION_CLASS
import kotlin.annotation.AnnotationTarget.CLASS
import kotlin.annotation.AnnotationTarget.FUNCTION
import kotlin.annotation.AnnotationTarget.PROPERTY_GETTER
import kotlin.annotation.AnnotationTarget.PROPERTY_SETTER
import no.nav.security.token.support.core.api.Protected
import no.nav.security.token.support.core.api.ProtectedWithClaims
import no.nav.security.token.support.core.api.Unprotected

@Protected
@Target(ANNOTATION_CLASS, CLASS, FUNCTION, PROPERTY_GETTER, PROPERTY_SETTER)
@Retention(RUNTIME)
internal annotation class ProtectedMeta

@ProtectedWithClaims(issuer = "issuer1", claimMap = ["acr=Level4"])
@Target(ANNOTATION_CLASS, CLASS, FUNCTION, PROPERTY_GETTER, PROPERTY_SETTER)
@Retention(RUNTIME)
internal annotation class ProtectedWithClaimsMeta

@Unprotected
@Target(ANNOTATION_CLASS, CLASS, FUNCTION, PROPERTY_GETTER, PROPERTY_SETTER)
@Retention(RUNTIME)
internal annotation class UnprotectedMeta