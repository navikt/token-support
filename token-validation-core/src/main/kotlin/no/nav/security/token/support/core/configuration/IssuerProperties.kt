package no.nav.security.token.support.core.configuration

import jakarta.validation.Validation
import java.net.URL
import java.util.Objects
import java.util.concurrent.TimeUnit.MINUTES
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import no.nav.security.token.support.core.JwtTokenConstants.AUTHORIZATION_HEADER
import no.nav.security.token.support.core.configuration.IssuerProperties.JwksCache.Companion.EMPTY_CACHE
import no.nav.security.token.support.core.configuration.IssuerProperties.Validation.Companion.EMPTY

class IssuerProperties @JvmOverloads constructor(val discoveryUrl : URL,
                                                 val acceptedAudience : List<String> = listOf(),
                                                 cookieName : String? = null,
                                                 val headerName : String = AUTHORIZATION_HEADER,
                                                 val validation : Validation = EMPTY,
                                                 val jwksCache : JwksCache = EMPTY_CACHE,
                                                 val proxyUrl: URL? = null,
                                                 val usePlaintextForHttps: Boolean = false) {

    init {
        cookieName?.let { throw IllegalArgumentException("Cookie-support is discontinued, please remove $it from your configuration now") }
    }

    override fun toString() = "IssuerProperties(discoveryUrl=$discoveryUrl, acceptedAudience=$acceptedAudience, headerName=$headerName, proxyUrl=$proxyUrl, usePlaintextForHttps=$usePlaintextForHttps, validation=$validation, jwksCache=$jwksCache)"

    class Validation(val optionalClaims : List<String> = emptyList()) {

        val isConfigured = optionalClaims.isNotEmpty()

        override fun equals(other : Any?) : Boolean {
            if (this === other) return true
            if (other == null || javaClass != other.javaClass) return false
            val that = other as Validation
            return optionalClaims == that.optionalClaims
        }

        override fun hashCode() = Objects.hash(optionalClaims)

        override fun toString() = "IssuerProperties.Validation(optionalClaims=$optionalClaims)"

        companion object {

            @JvmField
            val EMPTY : Validation = Validation(emptyList())
        }
    }

    class JwksCache(val lifespan : Long?, val refreshTime : Long?) {

        val isConfigured = lifespan != null && refreshTime != null

        val lifespanMillis  = MINUTES.toMillis(lifespan!!)

        val refreshTimeMillis = MINUTES.toMillis(refreshTime!!)

        override fun equals(other : Any?) : Boolean {
            if (this === other) return true
            if (other == null || javaClass != other.javaClass) return false
            val jwksCache = other as JwksCache
            return lifespan == jwksCache.lifespan && refreshTime == jwksCache.refreshTime
        }

        override fun hashCode() = Objects.hash(lifespan, refreshTime)

        override fun toString() = "${javaClass.simpleName} [lifespan=$lifespan,refreshTime=$refreshTime]"

        companion object {

            @JvmField val EMPTY_CACHE  = JwksCache(15, 5)
        }
    }
}