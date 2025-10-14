package no.nav.security.token.support.v3


import com.nimbusds.jose.util.ResourceRetriever
import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.config.*
import io.ktor.server.response.*
import java.net.URI
import no.nav.security.token.support.core.JwtTokenConstants.AUTHORIZATION_HEADER
import no.nav.security.token.support.core.configuration.IssuerProperties
import no.nav.security.token.support.core.configuration.IssuerProperties.JwksCache
import no.nav.security.token.support.core.configuration.IssuerProperties.Validation
import no.nav.security.token.support.core.configuration.MultiIssuerConfiguration
import no.nav.security.token.support.core.configuration.ProxyAwareResourceRetriever
import no.nav.security.token.support.core.context.TokenValidationContext
import no.nav.security.token.support.core.context.TokenValidationContextHolder
import no.nav.security.token.support.core.exceptions.JwtTokenInvalidClaimException
import no.nav.security.token.support.core.exceptions.JwtTokenMissingException
import no.nav.security.token.support.core.http.HttpRequest
import no.nav.security.token.support.core.utils.JwtTokenUtil.getJwtToken
import no.nav.security.token.support.core.validation.JwtTokenAnnotationHandler
import no.nav.security.token.support.core.validation.JwtTokenValidationHandler
import no.nav.security.token.support.v3.TokenSupportAuthenticationProvider.ProviderConfiguration
import org.slf4j.LoggerFactory

data class TokenValidationContextPrincipal(val context: TokenValidationContext) : Principal

private val log = LoggerFactory.getLogger(TokenSupportAuthenticationProvider::class.java.name)

class TokenSupportAuthenticationProvider(providerConfig: ProviderConfiguration, config: ApplicationConfig,
                                         private val requiredClaims: RequiredClaims? = null,
                                         private val additionalValidation: ((TokenValidationContext) -> Boolean)? = null,
                                         resourceRetriever: ResourceRetriever) : AuthenticationProvider(providerConfig) {

    private val jwtTokenValidationHandler: JwtTokenValidationHandler
    private val jwtTokenExpiryThresholdHandler: JwtTokenExpiryThresholdHandler

    init {
        jwtTokenValidationHandler = JwtTokenValidationHandler(MultiIssuerConfiguration(config.asIssuerProps(), resourceRetriever))

        val expiryThreshold = config.propertyOrNull("no.nav.security.jwt.expirythreshold")?.getString()?.toInt() ?: -1
        jwtTokenExpiryThresholdHandler = JwtTokenExpiryThresholdHandler(expiryThreshold)
    }

    class ProviderConfiguration internal constructor(name: String?) : Config(name)

    override suspend fun onAuthenticate(context: AuthenticationContext) {
        val applicationCall = context.call
        val tokenValidationContext = jwtTokenValidationHandler.getValidatedTokens(
            JwtTokenHttpRequest( applicationCall.request.headers)
        )
        try {
            if (tokenValidationContext.hasValidToken()) {
                if (requiredClaims != null) {
                    RequiredClaimsHandler(InternalTokenValidationContextHolder(tokenValidationContext)).handleRequiredClaims(
                        requiredClaims
                    )
                }
                if (additionalValidation != null) {
                    if (!additionalValidation.invoke(tokenValidationContext)) {
                        throw AdditionalValidationReturnedFalse()
                    }
                }
                jwtTokenExpiryThresholdHandler.addHeaderOnTokenExpiryThreshold(applicationCall, tokenValidationContext)
                context.principal(TokenValidationContextPrincipal(tokenValidationContext))
            }
        } catch (e: Throwable) {
            log.trace("Token verification failed: {}", e.message ?: e.javaClass.simpleName)
        }
        context.challenge("JWTAuthKey", AuthenticationFailedCause.InvalidCredentials) { authenticationProcedureChallenge, call ->
            call.respond(UnauthorizedResponse())
            authenticationProcedureChallenge.complete()
        }
    }
}

fun AuthenticationConfig.tokenValidationSupport(name: String? = null, config: ApplicationConfig, requiredClaims: RequiredClaims? = null,
                                                additionalValidation: ((TokenValidationContext) -> Boolean)? = null,
                                                resourceRetriever: ResourceRetriever = ProxyAwareResourceRetriever(System.getenv("HTTP_PROXY")?.let { URI.create(it).toURL() })) {
    register(TokenSupportAuthenticationProvider(ProviderConfiguration(name), config, requiredClaims, additionalValidation, resourceRetriever))
}


data class RequiredClaims(val issuer: String, val claimMap: Array<String>, val combineWithOr: Boolean = false)

data class IssuerConfig(
    val name: String,
    val discoveryUrl: String,
    val acceptedAudience: List<String> = emptyList(),
    val optionalClaims: List<String> = emptyList(),
)

class TokenSupportConfig(vararg issuers: IssuerConfig) : MapApplicationConfig(
    *(issuers.mapIndexed { index, issuerConfig ->
        listOf(
            "no.nav.security.jwt.issuers.$index.issuer_name" to issuerConfig.name,
            "no.nav.security.jwt.issuers.$index.discoveryurl" to issuerConfig.discoveryUrl,
            "no.nav.security.jwt.issuers.$index.accepted_audience" to
                issuerConfig.acceptedAudience.joinToString(","),
            "no.nav.security.jwt.issuers.$index.validation.optional_claims" to
                issuerConfig.optionalClaims.joinToString(","),
        )
    }.flatten().plus("no.nav.security.jwt.issuers.size" to issuers.size.toString()).toTypedArray())
)

private class InternalTokenValidationContextHolder(private var tokenValidationContext: TokenValidationContext) : TokenValidationContextHolder {
    override fun getTokenValidationContext() = tokenValidationContext
    override fun setTokenValidationContext(tokenValidationContext: TokenValidationContext?) {
        tokenValidationContext?.let { this.tokenValidationContext = tokenValidationContext }
    }
}

internal class AdditionalValidationReturnedFalse : RuntimeException()

internal class RequiredClaimsException(message: String, cause: Throwable) : RuntimeException(message, cause)
internal class RequiredClaimsHandler(private val tokenValidationContextHolder: TokenValidationContextHolder) : JwtTokenAnnotationHandler(tokenValidationContextHolder) {
    internal fun handleRequiredClaims(requiredClaims: RequiredClaims) {
        runCatching {
            with(requiredClaims) {
                log.debug("Checking required claims for issuer: {}, claims: {}, combineWithOr: {}", issuer, claimMap, combineWithOr)
                val jwtToken = getJwtToken(issuer, tokenValidationContextHolder)
                if (jwtToken.isEmpty) {
                    throw JwtTokenMissingException("No valid token found in validation context")
                }
                if (!handleProtectedWithClaims(issuer, claimMap, combineWithOr, jwtToken.get()))
                    throw JwtTokenInvalidClaimException("Required claims not present in token. " + requiredClaims.claimMap.entries.joinToString())
            }
        }.getOrElse {  e -> throw RequiredClaimsException(e.message ?: "", e) }
    }
}

internal data class JwtTokenHttpRequest(private val headers: Headers) : HttpRequest {
    override fun getHeader(headerName: String) = headers[headerName]
}

fun ApplicationConfig.asIssuerProps(): Map<String, IssuerProperties> = configList("no.nav.security.jwt.issuers")
    .associate {
        it.property("issuer_name").getString() to IssuerProperties(
            URI.create(it.property("discoveryurl").getString()).toURL(),
            it.propertyOrNull("accepted_audience")?.getString()
                ?.split(",")
                ?.filter { aud -> aud.isNotEmpty() }
                ?: emptyList(),
           null,
            it.propertyOrNull("header_name")?.getString() ?: AUTHORIZATION_HEADER,
            Validation(it.propertyOrNull("validation.optional_claims")?.getString()
                ?.split(",")
                ?.filter { claim -> claim.isNotEmpty() }
                ?: emptyList()),
            JwksCache(it.propertyOrNull("jwks_cache.lifespan")?.getString()?.toLong() ?: 15, it.propertyOrNull("jwks_cache.refreshtime")?.getString()?.toLong() ?: 5))
    }