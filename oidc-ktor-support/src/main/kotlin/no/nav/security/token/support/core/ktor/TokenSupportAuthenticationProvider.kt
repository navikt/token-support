package no.nav.security.token.support.core.ktor

import io.ktor.application.call
import io.ktor.auth.*
import io.ktor.config.ApplicationConfig
import io.ktor.http.CookieEncoding
import io.ktor.http.Headers
import io.ktor.http.decodeCookieValue
import io.ktor.request.RequestCookies
import io.ktor.response.respond
import no.nav.security.token.support.core.configuration.IssuerProperties
import no.nav.security.token.support.core.configuration.MultiIssuerConfiguration
import no.nav.security.token.support.core.configuration.ProxyAwareResourceRetriever
import no.nav.security.token.support.core.context.JwtTokenValidationContext
import no.nav.security.token.support.core.http.HttpRequest
import no.nav.security.token.support.core.validation.JwtTokenValidationHandler
import java.net.URL

data class OIDCValidationContextPrincipal(val context: JwtTokenValidationContext) : Principal

@io.ktor.util.KtorExperimentalAPI
class TokenSupportAuthenticationProvider(name: String?, config: ApplicationConfig) : AuthenticationProvider(name) {
    private val multiIssuerConfiguration: MultiIssuerConfiguration
    internal val jwtTokenValidationHandler: JwtTokenValidationHandler

    init {
        val issuerPropertiesMap: MutableMap<String, IssuerProperties> = hashMapOf()
        for (issuerConfig in config.configList("no.nav.security.oidc.issuers")) {
            issuerPropertiesMap[issuerConfig.property("issuer_name").getString()] = IssuerProperties(
                URL(issuerConfig.property("discoveryurl").getString()),
                listOf(issuerConfig.property("accepted_audience").getString()),
                issuerConfig.property("cookie_name").getString()
            )
        }

        multiIssuerConfiguration = MultiIssuerConfiguration(issuerPropertiesMap, ProxyAwareResourceRetriever().apply {
            // TODO:
            //proxyUrl = null
        })
        jwtTokenValidationHandler = JwtTokenValidationHandler(multiIssuerConfiguration)
    }

}

@io.ktor.util.KtorExperimentalAPI
fun Authentication.Configuration.oidcSupport(
    name: String? = null,
    config: ApplicationConfig
) {
    val provider = TokenSupportAuthenticationProvider(name, config)
    provider.pipeline.intercept(AuthenticationPipeline.RequestAuthentication) { context ->
        val oidcValidationContext = provider.jwtTokenValidationHandler.getValidatedTokens(
            JwtTokenHttpRequest(call.request.cookies, call.request.headers)
        )
        if (oidcValidationContext.hasValidToken()) {
            context.principal(OIDCValidationContextPrincipal(oidcValidationContext))
            return@intercept
        }
        context.challenge("JWTAuthKey", AuthenticationFailedCause.InvalidCredentials) {
            call.respond(UnauthorizedResponse())
            it.complete()
        }
    }
    register(provider)
}

data class NameValueCookie(@JvmField val name: String, @JvmField val value: String) : HttpRequest.NameValue {
    override fun getName(): String = name
    override fun getValue(): String = value
}

data class JwtTokenHttpRequest(private val cookies : RequestCookies, private val headers : Headers) : HttpRequest {
    @io.ktor.util.KtorExperimentalAPI
    override fun getCookies() =
        cookies.rawCookies.map { NameValueCookie(it.key, decodeCookieValue(it.value, CookieEncoding.URI_ENCODING)) }.toTypedArray()
    override fun getHeader(name: String) = headers[name]
}
