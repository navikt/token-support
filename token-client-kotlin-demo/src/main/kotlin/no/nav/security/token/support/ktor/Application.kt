package no.nav.security.token.support.ktor

import com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL
import com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES
import com.fasterxml.jackson.databind.SerializationFeature.INDENT_OUTPUT
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.GrantType.CLIENT_CREDENTIALS
import com.nimbusds.oauth2.sdk.GrantType.JWT_BEARER
import com.nimbusds.oauth2.sdk.GrantType.TOKEN_EXCHANGE
import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.http.ContentType.Application.Json
import io.ktor.http.HttpStatusCode.Companion.OK
import io.ktor.serialization.jackson.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import no.nav.security.mock.oauth2.MockOAuth2Server
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenResponse
import no.nav.security.token.support.ktor.oauth.ClientConfig
import no.nav.security.token.support.v2.TokenValidationContextPrincipal
import no.nav.security.token.support.v2.tokenValidationSupport
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ContentNegotiationClient
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation as ContentNegotiationServer

fun main(args: Array<String>): Unit = io.ktor.server.netty.EngineMain.main(args)

val defaultHttpClient = HttpClient(CIO) {
    install(ContentNegotiationClient) {
        jackson {
            configure(FAIL_ON_UNKNOWN_PROPERTIES, false)
            setSerializationInclusion(NON_NULL)
        }
    }
}

val defaultMapper = jacksonObjectMapper().apply {
    configure(INDENT_OUTPUT, true)
    configure(FAIL_ON_UNKNOWN_PROPERTIES, false)
    setSerializationInclusion(NON_NULL)
}

@Suppress("unused") // Referenced in application.conf
fun Application.module() {

    // mock oAuth2 server for demo app
    MockOAuth2Server().start(1111)

    install(ContentNegotiationServer) {
        register(Json, JacksonConverter(defaultMapper))
    }
    val config = environment.config

    install(Authentication) {
        tokenValidationSupport(config = config)
    }

    val oauth2Client = checkNotNull(ClientConfig(config, defaultHttpClient).clients["issuer1"])

    routing {
        get("/client_credentials") {
            val oAuth2Response = oauth2Client.clientCredentials("targetscope")
            call.respond(OK, DemoTokenResponse(CLIENT_CREDENTIALS.value, oAuth2Response))
        }
        authenticate {
            get("/onbehalfof") {
                val token = call.principal<TokenValidationContextPrincipal>().asTokenString()
                val oAuth2Response = oauth2Client.onBehalfOf(token, "targetscope")
                call.respond(OK, DemoTokenResponse(JWT_BEARER.value, oAuth2Response))
            }
            get("/tokenx") {
                val token = call.principal<TokenValidationContextPrincipal>().asTokenString()
                val oAuth2Response = oauth2Client.tokenExchange(token, "targetaudience")
                call.respond(OK, DemoTokenResponse(TOKEN_EXCHANGE.value, oAuth2Response))
            }
        }
    }
}

data class DemoTokenResponse(val grantType: String, val tokenResponse: OAuth2AccessTokenResponse) {
    val claims = SignedJWT.parse(tokenResponse.access_token).jwtClaimsSet.claims
}

internal fun TokenValidationContextPrincipal?.asTokenString() =
    this?.context?.firstValidToken?.encodedToken
        ?: throw RuntimeException("no token found in call context")