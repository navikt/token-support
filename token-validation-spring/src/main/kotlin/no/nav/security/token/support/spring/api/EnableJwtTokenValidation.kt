package no.nav.security.token.support.spring.api

import no.nav.security.token.support.spring.EnableJwtTokenValidationConfiguration
import org.springframework.context.annotation.Import
import java.lang.annotation.Inherited
import java.lang.annotation.Retention
import java.lang.annotation.RetentionPolicy.RUNTIME
import kotlin.annotation.AnnotationTarget.ANNOTATION_CLASS
import kotlin.annotation.AnnotationTarget.CLASS

@MustBeDocumented
@Inherited
@Retention(RUNTIME)
@Target(ANNOTATION_CLASS, CLASS)
@Import(EnableJwtTokenValidationConfiguration::class)
annotation class EnableJwtTokenValidation(val ignore: Array<String> = ["org.springframework"], val registerTokenXInteeceptor: Boolean = true)