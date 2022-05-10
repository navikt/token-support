package no.nav.security.token.support.ktor

import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import com.nimbusds.jwt.SignedJWT
import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.auth.Authentication
import io.ktor.server.auth.authenticate
import io.ktor.server.auth.principal
import io.ktor.server.response.respond
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation as ContentNegotiationServer
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ContentNegotiationClient
import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.ktor.serialization.jackson.JacksonConverter
import no.nav.security.mock.oauth2.MockOAuth2Server
import no.nav.security.token.support.client.core.OAuth2GrantType
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenResponse
import no.nav.security.token.support.ktor.oauth.ClientConfig

fun main(args: Array<String>): Unit = io.ktor.server.netty.EngineMain.main(args)

val defaultHttpClient = HttpClient(CIO) {
    install(ContentNegotiationClient) {
        register(ContentType.Application.Json, JacksonConverter(
            jacksonObjectMapper()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                .setSerializationInclusion(JsonInclude.Include.NON_NULL)
        )
        )
    }
}

val defaultMapper: ObjectMapper = jacksonObjectMapper().apply {
    configure(SerializationFeature.INDENT_OUTPUT, true)
    configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
    setSerializationInclusion(JsonInclude.Include.NON_NULL)
}

@Suppress("unused") // Referenced in application.conf
fun Application.module() {

    // mock oAuth2 server for demo app
    MockOAuth2Server().start(1111)

    val env = this.environment

    install(ContentNegotiationServer) {
        register(ContentType.Application.Json, JacksonConverter(defaultMapper))
    }

    install(Authentication) {
        tokenValidationSupport(config = env.config)
    }

    val oauth2Client = checkNotNull(ClientConfig(environment.config, defaultHttpClient).clients["issuer1"])

    routing {
        get("/client_credentials") {
            val oAuth2Response = oauth2Client.clientCredentials("targetscope")
            call.respond(
                HttpStatusCode.OK,
                DemoTokenResponse(
                    OAuth2GrantType.CLIENT_CREDENTIALS.value,
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
                        OAuth2GrantType.JWT_BEARER.value,
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
                        OAuth2GrantType.TOKEN_EXCHANGE.value,
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
    this?.context?.firstValidToken?.map { it.tokenAsString }?.orElse(null)
        ?: throw RuntimeException("no token found in call context")