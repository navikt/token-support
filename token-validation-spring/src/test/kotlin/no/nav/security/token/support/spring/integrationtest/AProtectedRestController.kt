package no.nav.security.token.support.spring.integrationtest

import no.nav.security.token.support.core.api.ProtectedWithClaims
import no.nav.security.token.support.core.api.RequiredIssuers
import no.nav.security.token.support.core.api.Unprotected
import no.nav.security.token.support.spring.ProtectedRestController
import org.springframework.web.bind.annotation.GetMapping

@ProtectedRestController(issuer = AProtectedRestController.ISSUER_SHORTNAME)
class AProtectedRestController {
    @GetMapping(PROTECTED)
    fun protectedMethod() = "protected"

    @ProtectedWithClaims(issuer = ISSUER_SHORTNAME, claimMap = ["importantclaim=vip", "acr=Level4"])
    @GetMapping(PROTECTED_WITH_CLAIMS)
    fun protectedWithClaimsMethod() = "protected with some required claims"

    @ProtectedWithClaims(issuer = ISSUER_SHORTNAME2)
    @GetMapping(PROTECTED_WITH_CLAIMS2)
    fun protectedWithClaimsMethod2() = "protected with some required claims"

    @RequiredIssuers(
            ProtectedWithClaims(issuer = ISSUER_SHORTNAME2, claimMap = ["claim1=1", "claim2=2"]),
            ProtectedWithClaims(issuer = ISSUER_SHORTNAME, claimMap = ["claim1=3", "claim2=4"]))
    @GetMapping(PROTECTED_WITH_MULTIPLE)
    fun protectedWith2IssuersMethod() = "protected with some required claims"

    @ProtectedWithClaims(issuer = ISSUER_SHORTNAME3)
    @GetMapping(PROTECTED_WITH_CLAIMS3)
    fun protectedWithClaimsMethod3() = "protected with some required claims and configurable JWKSet"

    @ProtectedWithClaims(issuer = ISSUER_SHORTNAME, claimMap = ["claim1=1", "claim2=2"], combineWithOr = true)
    @GetMapping(PROTECTED_WITH_CLAIMS_ANY_CLAIMS)
    fun protectedWithClaimsAnyClaimMethod() = "protected with any of the registered claims"

    @Unprotected
    @GetMapping(UNPROTECTED)
    fun unprotectedMethod() = "unprotected"

    companion object {
        const val ISSUER_SHORTNAME = "knownissuer"
        private const val ISSUER_SHORTNAME2 = "knownissuer2"
        private const val ISSUER_SHORTNAME3 = "knownissuer3"
        const val UNPROTECTED = "/unprotected"
        const val PROTECTED = "/protected"
        const val PROTECTED_WITH_CLAIMS = "/protected/withclaims"
        const val PROTECTED_WITH_CLAIMS2 = "/protected/withclaims2"
        const val PROTECTED_WITH_CLAIMS3 = "/protected/withclaims3"
        const val PROTECTED_WITH_MULTIPLE = "/protected/withmultipleissuers"
        const val PROTECTED_WITH_CLAIMS_ANY_CLAIMS = "/protected/anyclaims"
    }
}