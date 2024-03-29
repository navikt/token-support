package no.nav.security.token.support.core.api

import no.nav.security.token.support.core.utils.Cluster
import kotlin.annotation.AnnotationRetention.RUNTIME
import kotlin.annotation.AnnotationTarget.CLASS
import kotlin.annotation.AnnotationTarget.FUNCTION
import kotlin.annotation.AnnotationTarget.PROPERTY_GETTER
import kotlin.annotation.AnnotationTarget.PROPERTY_SETTER

@Retention(RUNTIME)
@Target(CLASS, FUNCTION, PROPERTY_GETTER, PROPERTY_SETTER)
@Protected
@MustBeDocumented
annotation class ProtectedWithClaims(val issuer : String,
                                     /**
                                      * Required claims in token in key=value format.
                                      * If the value is an asterisk (*), it checks that the required key is present.
                                      * @return array containing claims as key=value
                                      */
                                     val claimMap : Array<String> = [], val excludedClusters : Array<Cluster> = [],
                                     /**
                                      * How to check for the presence of claims,
                                      * default is false which will require all claims in the list
                                      * to be present in token. If set to true, any claim in the list
                                      * will suffice.
                                      *
                                      * @return boolean
                                      */
                                     val combineWithOr : Boolean = false)