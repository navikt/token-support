package no.nav.security.token.support.core.exceptions

import no.nav.security.token.support.core.api.ProtectedWithClaims
import no.nav.security.token.support.core.api.RequiredIssuers

class JwtTokenInvalidClaimException(message : String) : RuntimeException(message) {
    constructor(ann : RequiredIssuers) : this("Required claims not present in token for any of ${issuersAndClaims(ann)}")

    constructor(ann : ProtectedWithClaims) : this("Required claims not present in token. ${listOf<String>(*ann.claimMap)}")

    companion object {
        private fun issuersAndClaims(ann: RequiredIssuers) = ann.value.associate { it.issuer to it.claimMap }
    }
}