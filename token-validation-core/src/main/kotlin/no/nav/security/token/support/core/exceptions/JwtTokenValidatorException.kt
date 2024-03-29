package no.nav.security.token.support.core.exceptions

import java.util.*

class JwtTokenValidatorException @JvmOverloads constructor(msg : String? = null, val expiryDate : Date? = null, cause : Throwable? = null) : RuntimeException(msg, cause) {
    constructor(msg : String, cause : Throwable) : this(msg, null,cause)
}