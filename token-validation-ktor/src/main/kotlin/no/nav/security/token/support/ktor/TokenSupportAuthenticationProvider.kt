package no.nav.security.token.support.ktor

import io.ktor.application.call
import io.ktor.auth.*
import io.ktor.config.ApplicationConfig
import io.ktor.config.MapApplicationConfig
import io.ktor.http.CookieEncoding
import io.ktor.http.Headers
import io.ktor.http.decodeCookieValue
import io.ktor.request.RequestCookies
import io.ktor.response.respond
import io.ktor.util.KtorExperimentalAPI
import no.nav.security.token.support.core.configuration.IssuerProperties
import no.nav.security.token.support.core.configuration.MultiIssuerConfiguration
import no.nav.security.token.support.core.configuration.ProxyAwareResourceRetriever
import no.nav.security.token.support.core.context.TokenValidationContext
import no.nav.security.token.support.core.context.TokenValidationContextHolder
import no.nav.security.token.support.core.http.HttpRequest
import no.nav.security.token.support.core.validation.JwtTokenAnnotationHandler
import no.nav.security.token.support.core.validation.JwtTokenValidationHandler
import org.slf4j.LoggerFactory
import java.net.URL

data class TokenValidationContextPrincipal(val context: TokenValidationContext) : Principal

@KtorExperimentalAPI
private val log = LoggerFactory.getLogger(TokenSupportAuthenticationProvider::class.java.name)

@KtorExperimentalAPI
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

    init {
        val issuerPropertiesMap: Map<String, IssuerProperties> = applicationConfig.configList("no.nav.security.jwt.issuers")
            .associate { issuerConfig ->
                issuerConfig.property("issuer_name").getString() to IssuerProperties(
                    URL(issuerConfig.property("discoveryurl").getString()),
                    issuerConfig.property("accepted_audience").getString().split(","),
                    issuerConfig.propertyOrNull("cookie_name")?.getString()
                )
            }
        jwtTokenValidationHandler = JwtTokenValidationHandler(
            MultiIssuerConfiguration(issuerPropertiesMap, resourceRetriever)
        )
    }

    class ProviderConfiguration internal constructor(name: String?): AuthenticationProvider.Configuration(name)
}

@KtorExperimentalAPI
fun Authentication.Configuration.tokenValidationSupport(
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
                context.principal(TokenValidationContextPrincipal(tokenValidationContext))
                return@intercept
            }
        } catch (e: Throwable) {
            val message = e.message ?: e.javaClass.simpleName
            log.trace("Token verification failed: {}", message)
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

@KtorExperimentalAPI
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
    }.flatMap { it }.plus("no.nav.security.jwt.issuers.size" to issuers.size.toString()).toTypedArray())
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
internal class RequiredClaimsHandler(tokenValidationContextHolder: TokenValidationContextHolder) :
    JwtTokenAnnotationHandler(tokenValidationContextHolder) {
    internal fun handleRequiredClaims(requiredClaims: RequiredClaims) {
        try {
            handleProtectedWithClaims(requiredClaims.issuer, requiredClaims.claimMap, requiredClaims.combineWithOr)
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
    @KtorExperimentalAPI
    override fun getCookies() =
        cookies.rawCookies.map {
            NameValueCookie(
                it.key,
                decodeCookieValue(it.value, CookieEncoding.URI_ENCODING)
            )
        }.toTypedArray()

    override fun getHeader(name: String) = headers[name]
}
