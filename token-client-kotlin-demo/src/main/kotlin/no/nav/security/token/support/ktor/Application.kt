package no.nav.security.token.support.ktor


import io.ktor.server.application.call
import com.fasterxml.jackson.annotation.JsonInclude.*
import com.fasterxml.jackson.annotation.JsonInclude.Include.*
import com.fasterxml.jackson.databind.DeserializationFeature.*
import com.fasterxml.jackson.databind.SerializationFeature.*
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.GrantType
import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.jackson.JacksonSerializer
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.auth.Authentication
import io.ktor.server.auth.authenticate
import io.ktor.server.routing.routing
import no.nav.security.mock.oauth2.MockOAuth2Server
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenResponse
import no.nav.security.token.support.ktor.oauth.ClientConfig
import no.nav.security.token.support.v2.TokenValidationContextPrincipal
import io.ktor.server.application.*
import io.ktor.server.auth.principal
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.response.respond
import io.ktor.server.routing.get
import no.nav.security.token.support.v2.tokenValidationSupport

fun main(args: Array<String>): Unit = io.ktor.server.netty.EngineMain.main(args)

val defaultHttpClient = HttpClient(CIO) {
    install(JsonFeature) {
        serializer = JacksonSerializer {
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

    install(ContentNegotiation) {
        register(ContentType.Application.Json, JacksonConverter(defaultMapper))
    }

    install(Authentication) {
        tokenValidationSupport(config = environment.config)
    }

    val oauth2Client = checkNotNull(ClientConfig(environment.config, defaultHttpClient).clients["issuer1"])

    routing {
        get("/client_credentials") {
            val oAuth2Response = oauth2Client.clientCredentials("targetscope")
            call.respond(
                HttpStatusCode.OK,
                DemoTokenResponse(
                    GrantType.CLIENT_CREDENTIALS.value,
                    oAuth2Response
                )
            )
        }
        authenticate {
            get("/onbehalfof") {
                val token = call.principal<TokenValidationContextPrincipal>().asTokenString()
                val oAuth2Response = oauth2Client.onBehalfOf(token, "targetscope")
                call.respond(
                    HttpStatusCode.OK,
                    DemoTokenResponse(
                        GrantType.JWT_BEARER.value,
                        oAuth2Response
                    )
                )
            }
            get("/tokenx") {
                val token = call.principal<TokenValidationContextPrincipal>().asTokenString()
                val oAuth2Response = oauth2Client.tokenExchange(token, "targetaudience")
                call.respond(
                    HttpStatusCode.OK,
                    DemoTokenResponse(
                        GrantType.TOKEN_EXCHANGE.value,
                        oAuth2Response
                    )
                )
            }
        }
    }
}

data class DemoTokenResponse(
    val grantType: String,
    val tokenResponse: OAuth2AccessTokenResponse
) {
    val claims: Map<String, Any> = SignedJWT.parse(tokenResponse.accessToken).jwtClaimsSet.claims
}

internal fun TokenValidationContextPrincipal?.asTokenString(): String =
    this?.context?.firstValidToken?.encodedToken
        ?: throw RuntimeException("no token found in call context")