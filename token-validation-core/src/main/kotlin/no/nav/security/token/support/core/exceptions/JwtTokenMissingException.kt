package no.nav.security.token.support.core.exceptions

import no.nav.security.token.support.core.api.RequiredIssuers

class JwtTokenMissingException @JvmOverloads constructor(message : String? = "No valid token found in validation context") : RuntimeException(message) {
    constructor(ann : RequiredIssuers) : this("No valid token found in validation context for any of the issuers ${ann.value.map { it.issuer }}")
}