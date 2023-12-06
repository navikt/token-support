package no.nav.security.token.support.core.validation

import java.util.AbstractMap.SimpleImmutableEntry
import java.util.concurrent.ConcurrentHashMap
import kotlin.collections.Map.Entry
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import no.nav.security.token.support.core.configuration.MultiIssuerConfiguration
import no.nav.security.token.support.core.context.TokenValidationContext
import no.nav.security.token.support.core.exceptions.IssuerConfigurationException
import no.nav.security.token.support.core.exceptions.JwtTokenValidatorException
import no.nav.security.token.support.core.http.HttpRequest
import no.nav.security.token.support.core.jwt.JwtToken
import no.nav.security.token.support.core.validation.JwtTokenRetriever.retrieveUnvalidatedTokens
import no.nav.security.token.support.core.validation.JwtTokenValidatorFactory.tokenValidator

class JwtTokenValidationHandler(private val config : MultiIssuerConfiguration) {

    fun getValidatedTokens(request : HttpRequest) =
        retrieveUnvalidatedTokens(config, request).run {
            with(mapNotNull(::validate)
                .associateByTo(ConcurrentHashMap(), { it.key }, { it.value })) {
                LOG.debug("Found {} tokens on request, number of validated tokens is {}", size, this@with.size)
                if (this@with.isEmpty() && isNotEmpty()) {
                    LOG.debug("Found {} unvalidated token(s) with issuer(s) {} on request, is this a configuration error?", size, map(JwtToken::issuer))
                }
                TokenValidationContext(this)
            }
        }

    private fun validate(jwtToken : JwtToken) : Entry<String, JwtToken>? {
       with(jwtToken) {
           try {
               LOG.debug("Check if token with issuer={} is present in config", issuer)
               if (config.getIssuer(issuer).isPresent) {
                   val issuerShortName = issuerConfiguration(issuer).name
                   LOG.debug("Found token from trusted issuer={} with shortName={} in request", issuer, issuerShortName)
                   tokenValidator(jwtToken).assertValidToken(encodedToken)
                   LOG.debug("Validated token from issuer[{}]", issuer)
                   return SimpleImmutableEntry(issuerShortName, this)
               }
               return null.also {
                   LOG.info("Found token from unknown issuer[{}], skipping validation.", issuer)
               }
           }
           catch (e : JwtTokenValidatorException) {
               return null.also {
                   LOG.info("Found invalid token for issuer [{}, expires at {}], message:{} ",issuer, e.expiryDate, e.message)
               }
           }
       }


    }

    private fun tokenValidator(jwtToken : JwtToken) = issuerConfiguration(jwtToken.issuer).tokenValidator

    private fun issuerConfiguration(issuer : String) = config.getIssuer(issuer)
        .orElseThrow { IssuerConfigurationException("Could not find IssuerConfiguration for issuer $issuer") }

    companion object {
        private val LOG : Logger = LoggerFactory.getLogger(JwtTokenValidationHandler::class.java)
    }
}