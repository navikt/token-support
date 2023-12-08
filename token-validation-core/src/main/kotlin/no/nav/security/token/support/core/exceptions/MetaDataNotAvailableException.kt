package no.nav.security.token.support.core.exceptions

import java.net.URL

class MetaDataNotAvailableException(msg : String, url : URL, e : Throwable) : RuntimeException("Could not retrieve metadata from $url. $msg", e) {
}