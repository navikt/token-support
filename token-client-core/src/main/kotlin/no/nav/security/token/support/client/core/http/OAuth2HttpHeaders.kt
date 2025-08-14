package no.nav.security.token.support.client.core.http

import java.lang.String.CASE_INSENSITIVE_ORDER
import java.util.*

class OAuth2HttpHeaders (val headers : Map<String,String>) {

    override fun equals(other : Any?) : Boolean {
        if (this === other) return true
        if (other == null || javaClass != other.javaClass) return false
        val that = other as OAuth2HttpHeaders
        return headers == that.headers
    }

    override fun hashCode() = Objects.hash(headers)

    override fun toString() = "${javaClass.getSimpleName()} [headers=$headers]"

    class Builder(private val headers : TreeMap<String, String> =  TreeMap(CASE_INSENSITIVE_ORDER)) {

        fun header(name : String, value : String) = this.also { headers.computeIfAbsent(name) { value }
        }
        fun build() = of(headers)
    }

    companion object {

        @JvmField
        val NONE = OAuth2HttpHeaders(emptyMap())
       @JvmStatic
        fun of(headers : Map<String, String>) = OAuth2HttpHeaders(headers)

        @JvmStatic
        fun builder() = Builder()
    }
}