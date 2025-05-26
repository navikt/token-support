package no.nav.security.token.support.spring

import no.nav.security.token.support.core.api.ProtectedWithClaims
import no.nav.security.token.support.core.api.Unprotected
import org.springframework.core.annotation.AliasFor
import org.springframework.http.MediaType.APPLICATION_JSON_VALUE
import org.springframework.http.MediaType.TEXT_PLAIN_VALUE
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import kotlin.annotation.AnnotationRetention.RUNTIME
import kotlin.annotation.AnnotationTarget.ANNOTATION_CLASS
import kotlin.annotation.AnnotationTarget.CLASS

@RestController
@MustBeDocumented
@ProtectedWithClaims(issuer = "must-be-set-to-issuer-short-name")
@Target(ANNOTATION_CLASS, CLASS)
@Retention(RUNTIME)
@RequestMapping
annotation class ProtectedRestController(@get: AliasFor(annotation = ProtectedWithClaims::class, attribute = "issuer") val issuer: String,
                                         @get: AliasFor(annotation = ProtectedWithClaims::class, attribute = "claimMap") val claimMap: Array<String> = ["acr=Level4"],
                                         @get: AliasFor(annotation = RequestMapping::class, attribute = "value") val value:  Array<String> = ["/"],
                                         @get: AliasFor(annotation = RequestMapping::class, attribute = "produces") val produces: Array<String> = [APPLICATION_JSON_VALUE])

@RestController
@MustBeDocumented
@Unprotected
@Target(ANNOTATION_CLASS, CLASS)
@Retention(RUNTIME)
@RequestMapping
annotation class UnprotectedRestController(@get: AliasFor(annotation = RequestMapping::class, attribute = "value") val value:  Array<String> = ["/"],
                                           @get: AliasFor(annotation = RequestMapping::class, attribute = "produces") val produces: Array<String> = [APPLICATION_JSON_VALUE])