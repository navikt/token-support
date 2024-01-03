package no.nav.security.token.support.spring.api

import java.lang.annotation.Inherited
import kotlin.annotation.AnnotationRetention.RUNTIME
import kotlin.annotation.AnnotationTarget.ANNOTATION_CLASS
import kotlin.annotation.AnnotationTarget.CLASS
import org.springframework.context.annotation.Import
import no.nav.security.token.support.spring.EnableJwtTokenValidationConfiguration

@MustBeDocumented
@Inherited
@Retention(RUNTIME)
@Target(ANNOTATION_CLASS, CLASS)
@Import(EnableJwtTokenValidationConfiguration::class)
annotation class EnableJwtTokenValidation(val ignore: Array<String> = ["org.springframework"])