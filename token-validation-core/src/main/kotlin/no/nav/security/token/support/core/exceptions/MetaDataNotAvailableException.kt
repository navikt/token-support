package no.nav.security.token.support.core.exceptions

import java.net.URL

class MetaDataNotAvailableException : RuntimeException {
    constructor(e : Exception?) : super(e)
    constructor(msg : String?, url : URL?, e : Exception?) : super(String.format("Could not retrieve metadata from url: %s. %s", url, msg), e)
}