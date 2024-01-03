package no.nav.security.token.support.core.http

/***
 * Abstraction interface for an HTTP request to avoid dependencies on specific implementations such as HttpServletRequest etc.
 */
interface HttpRequest {
    fun getHeader(headerName: String): String?
    fun getCookies(): Array<out NameValue>?

    interface NameValue {
        fun getName(): String
        fun getValue(): String
    }
}