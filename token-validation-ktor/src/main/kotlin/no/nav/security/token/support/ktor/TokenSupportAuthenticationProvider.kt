package no.nav.security.token.support.ktor

import io.ktor.server.application.call
import io.ktor.server.auth.AuthenticationFailedCause
import io.ktor.server.auth.UnauthorizedResponse
import io.ktor.http.CookieEncoding
import io.ktor.http.Headers
import io.ktor.http.decodeCookieValue
import io.ktor.server.auth.AuthenticationConfig
import io.ktor.server.auth.Authentication
import io.ktor.server.auth.AuthenticationContext
import io.ktor.server.auth.AuthenticationProvider
import io.ktor.server.auth.Principal
import io.ktor.server.config.ApplicationConfig
import io.ktor.server.config.MapApplicationConfig
import io.ktor.server.request.RequestCookies
import no.nav.security.token.support.core.context.TokenValidationContext
import no.nav.security.token.support.core.context.TokenValidationContextHolder
import no.nav.security.token.support.core.exceptions.JwtTokenInvalidClaimException
import no.nav.security.token.support.core.exceptions.JwtTokenMissingException
import no.nav.security.token.support.core.http.HttpRequest
import no.nav.security.token.support.core.utils.JwtTokenUtil.getJwtToken
import no.nav.security.token.support.core.validation.JwtTokenAnnotationHandler
import no.nav.security.token.support.core.validation.JwtTokenValidationHandler
import org.slf4j.LoggerFactory
import java.net.URL
import no.nav.security.token.support.core.configuration.IssuerProperties
import no.nav.security.token.support.core.configuration.MultiIssuerConfiguration
import no.nav.security.token.support.core.configuration.ProxyAwareResourceRetriever

data class TokenValidationContextPrincipal(val context: TokenValidationContext) : Principal

private val log = LoggerFactory.getLogger(TokenSupportAuthenticationProvider::class.java.name)

class TokenSupportAuthenticationProvider(
    providerConfig: ProviderConfiguration,
    applicationConfig: ApplicationConfig,
    resourceRetriever: ProxyAwareResourceRetriever
) : AuthenticationProvider(providerConfig) {

    @Deprecated("Provider should be built using configuration that need to be passed via constructor instead.")
    constructor(
        name: String?,
        config: ApplicationConfig,
        resourceRetriever: ProxyAwareResourceRetriever
    ): this(ProviderConfiguration(name),config, resourceRetriever)

    internal val jwtTokenValidationHandler: JwtTokenValidationHandler
    internal val jwtTokenExpiryThresholdHandler: JwtTokenExpiryThresholdHandler

    init {
        val issuerPropertiesMap: Map<String, IssuerProperties> = applicationConfig.asIssuerProps()
        jwtTokenValidationHandler = JwtTokenValidationHandler(
            MultiIssuerConfiguration(issuerPropertiesMap, resourceRetriever)
        )

        val expiryThreshold: Int = applicationConfig.propertyOrNull("no.nav.security.jwt.expirythreshold")?.getString()?.toInt() ?: -1
        jwtTokenExpiryThresholdHandler = JwtTokenExpiryThresholdHandler(expiryThreshold)
    }

    class ProviderConfiguration internal constructor(name: String?): Config(name)

    override suspend fun onAuthenticate(context: AuthenticationContext) {
        TODO("Not yet implemented")
    }

}

//TODO This is the only thing not wokring with ktor 2.0.0 what
fun Authentication.AuthenticationConfig.tokenValidationSupport(
    name: String? = null,
    config: ApplicationConfig,
    requiredClaims: RequiredClaims? = null,
    additionalValidation: ((TokenValidationContext) -> Boolean)? = null,
    resourceRetriever: ProxyAwareResourceRetriever = ProxyAwareResourceRetriever(
        System.getenv("HTTP_PROXY")?.let { URL(it) }
    )
) {
    val provider = TokenSupportAuthenticationProvider(
        TokenSupportAuthenticationProvider.ProviderConfiguration(name),
        config,
        resourceRetriever
    )
    provider.pipeline.intercept(AuthenticationPipeline.RequestAuthentication) { context ->
        val tokenValidationContext = provider.jwtTokenValidationHandler.getValidatedTokens(
            JwtTokenHttpRequest(call.request.cookies, call.request.headers)
        )
        try {
            if (tokenValidationContext.hasValidToken()) {
                if (requiredClaims != null) {
                    RequiredClaimsHandler(InternalTokenValidationContextHolder(tokenValidationContext)).handleRequiredClaims(
                        requiredClaims
                    )
                }
                if (additionalValidation != null) {
                    if (!additionalValidation(tokenValidationContext)) {
                        throw AdditionalValidationReturnedFalse()
                    }
                }
                provider.jwtTokenExpiryThresholdHandler.addHeaderOnTokenExpiryThreshold(call, tokenValidationContext)
                context.principal(TokenValidationContextPrincipal(tokenValidationContext))
                return@intercept
            }
        } catch (e: Throwable) {
            val message = e.message ?: e.javaClass.simpleName
            log.debug("Token verification failed: {}", message)
        }
        context.challenge("JWTAuthKey", AuthenticationFailedCause.InvalidCredentials) {
            call.respond(UnauthorizedResponse())
            it.complete()
        }
    }
    register(provider)
}


data class RequiredClaims(val issuer: String, val claimMap: Array<String>, val combineWithOr: Boolean = false)

data class IssuerConfig(
    val name: String,
    val discoveryUrl: String,
    val acceptedAudience: List<String>,
    val cookieName: String? = null
)

class TokenSupportConfig(vararg issuers: IssuerConfig) : MapApplicationConfig(
    *(issuers.mapIndexed { index, issuerConfig ->
        listOf(
            "no.nav.security.jwt.issuers.$index.issuer_name" to issuerConfig.name,
            "no.nav.security.jwt.issuers.$index.discoveryurl" to issuerConfig.discoveryUrl,
            "no.nav.security.jwt.issuers.$index.accepted_audience" to issuerConfig.acceptedAudience.joinToString(",")//,
        ).let {
            if (issuerConfig.cookieName != null) {
                it.plus("no.nav.security.jwt.issuers.$index.cookie_name" to issuerConfig.cookieName)
            } else {
                it
            }
        }
    }.flatten().plus("no.nav.security.jwt.issuers.size" to issuers.size.toString()).toTypedArray())
)

private class InternalTokenValidationContextHolder(private var tokenValidationContext: TokenValidationContext) :
    TokenValidationContextHolder {
    override fun getTokenValidationContext() = tokenValidationContext
    override fun setTokenValidationContext(tokenValidationContext: TokenValidationContext?) {
        this.tokenValidationContext = tokenValidationContext!!
    }
}

internal class AdditionalValidationReturnedFalse : RuntimeException()

internal class RequiredClaimsException(message: String, cause: Exception) : RuntimeException(message, cause)
internal class RequiredClaimsHandler(private val tokenValidationContextHolder: TokenValidationContextHolder) :
    JwtTokenAnnotationHandler(tokenValidationContextHolder) {
    internal fun handleRequiredClaims(requiredClaims: RequiredClaims) {
        try {
			val jwtToken = getJwtToken(requiredClaims.issuer, tokenValidationContextHolder)
            if (jwtToken.isEmpty) {
                throw  JwtTokenMissingException("no valid token found in validation context")
            }
            if (!handleProtectedWithClaims(requiredClaims.issuer, requiredClaims.claimMap, requiredClaims.combineWithOr,jwtToken.get())) 
                throw  JwtTokenInvalidClaimException("required claims not present in token." + requiredClaims.claimMap)
            
        } catch (e: RuntimeException) {
            throw RequiredClaimsException(e.message ?: "", e)
        }
    }
}

internal data class NameValueCookie(@JvmField val name: String, @JvmField val value: String) : HttpRequest.NameValue {
    override fun getName(): String = name
    override fun getValue(): String = value
}

internal data class JwtTokenHttpRequest(private val cookies: RequestCookies, private val headers: Headers) :
    HttpRequest {
    override fun getCookies() =
        cookies.rawCookies.map {
            NameValueCookie(
                it.key,
                decodeCookieValue(it.value, CookieEncoding.URI_ENCODING)
            )
        }.toTypedArray()

    override fun getHeader(name: String) = headers[name]
}

fun ApplicationConfig.asIssuerProps(): Map<String, IssuerProperties> = this.configList("no.nav.security.jwt.issuers")
    .associate { issuerConfig ->
        issuerConfig.property("issuer_name").getString() to IssuerProperties(
            URL(issuerConfig.property("discoveryurl").getString()),
            issuerConfig.property("accepted_audience").getString().split(","),
            issuerConfig.propertyOrNull("cookie_name")?.getString(),
            IssuerProperties.Validation(issuerConfig.propertyOrNull("validation.optional_claims")?.getString()?.split(",") ?: emptyList()),
            IssuerProperties.JwksCache(
                issuerConfig.propertyOrNull("jwks_cache.lifespan")?.getString()?.toLong(),
                issuerConfig.propertyOrNull("jwks_cache.refreshtime")?.getString()?.toLong()
            )
        )
    }