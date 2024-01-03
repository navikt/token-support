package no.nav.security.token.support.core.validation

import java.util.Optional
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import no.nav.security.token.support.core.configuration.MultiIssuerConfiguration
import no.nav.security.token.support.core.http.HttpRequest
import no.nav.security.token.support.core.jwt.JwtToken

object JwtTokenRetriever {

    private val LOG : Logger = LoggerFactory.getLogger(JwtTokenRetriever::class.java)
    private const val BEARER = "Bearer"

   @JvmStatic
    fun retrieveUnvalidatedTokens(config: MultiIssuerConfiguration, request: HttpRequest) =
        getTokensFromHeader(config, request) + getTokensFromCookies(config, request)

    private fun getTokensFromHeader(config: MultiIssuerConfiguration, request: HttpRequest): List<JwtToken> = try {
        LOG.debug("Checking authorization header for tokens using config {}", config)
        val issuer = config.issuers.values.firstOrNull { request.getHeader(it.headerName) != null }.let { Optional.ofNullable(it) }
        if (issuer.isPresent) {
            val headerValues = request.getHeader(issuer.get().headerName)?.split(",") ?: emptyList()
            extractBearerTokens(headerValues)
                .map(::JwtToken)
                .filterNot { config.issuers[it.issuer] == null }
        } else {
            emptyList<JwtToken>().also { LOG.debug("No tokens found in authorization header")  }
        }
    } catch (e: Exception) {
        emptyList<JwtToken>().also {
            LOG.warn("Received exception when attempting to extract and parse token from Authorization header", e)
        }
    }
    private fun getTokensFromCookies(config: MultiIssuerConfiguration, request: HttpRequest) = try {
        request.getCookies()?.asList()
            ?.filter { containsCookieName(config, it.getName()) }
            ?.map { JwtToken(it.getValue()) }
            ?: emptyList<JwtToken>().also {
                LOG.debug("No tokens found in cookies")
            }
    } catch (e: Exception) {
        LOG.warn("Received exception when attempting to extract and parse token from cookie", e)
        listOf()
    }

    private fun containsCookieName(configuration: MultiIssuerConfiguration, cookieName: String) =
        configuration.issuers.values.any {
            cookieName.equals(it.cookieName, ignoreCase = true)
        }

    private fun extractBearerTokens(headerValues: List<String>) =
        headerValues
        .map { it.split(" ") }
        .filter { it.size == 2 && it[0].equals(BEARER, ignoreCase = true) }
        .map { it[1].trim() }
}