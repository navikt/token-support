package no.nav.security.token.support.core.exceptions

import java.util.Arrays
import no.nav.security.token.support.core.api.ProtectedWithClaims
import no.nav.security.token.support.core.api.RequiredIssuers

class JwtTokenMissingException @JvmOverloads constructor(message : String? = "No valid token found in validation context") : RuntimeException(message) {
    constructor(ann : RequiredIssuers) : this("No valid token found in validation context for any of the issuers ${issuers(ann)}")

    companion object {

        private fun issuers(ann: RequiredIssuers) = ann.value.map { it.issuer }
    }
}