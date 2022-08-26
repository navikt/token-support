package no.nav.security.token.support.spring.api

import java.lang.annotation.Inherited
import no.nav.security.token.support.spring.EnableJwtTokenValidationConfiguration
import org.springframework.context.annotation.Import
import kotlin.annotation.AnnotationTarget.ANNOTATION_CLASS
import kotlin.annotation.AnnotationTarget.CLASS

@MustBeDocumented
@Inherited
@Retention(AnnotationRetention.RUNTIME)
@Target(ANNOTATION_CLASS, CLASS)
@Import(EnableJwtTokenValidationConfiguration::class)
annotation class EnableJwtTokenValidation(val ignore: Array<String> = ["org.springframework"])