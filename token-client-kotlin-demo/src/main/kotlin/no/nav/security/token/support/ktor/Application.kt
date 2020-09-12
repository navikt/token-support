package no.nav.security.token.support.ktor

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.ktor.application.Application
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.features.ContentNegotiation
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.jackson.JacksonConverter
import io.ktor.response.respond
import io.ktor.routing.get
import io.ktor.routing.routing
import io.ktor.util.KtorExperimentalAPI
import no.nav.security.mock.oauth2.MockOAuth2Server
import no.nav.security.token.support.ktor.utils.cacheFor
import no.nav.security.token.support.ktor.utils.configFor
import no.nav.security.token.support.ktor.http.DefaultOAuth2HttpClient
import no.nav.security.token.support.ktor.jwt.ClientAssertion
import no.nav.security.token.support.ktor.model.TokenResponse
import no.nav.security.token.support.ktor.oauth.OAuth2AccessTokenClient
import no.nav.security.token.support.ktor.oauth.OAuth2ClientProperties
import no.nav.security.token.support.ktor.oauth.TokenResolver

fun main(args: Array<String>): Unit = io.ktor.server.netty.EngineMain.main(args)

@KtorExperimentalAPI
@Suppress("unused") // Referenced in application.conf
fun Application.module() {

    install(ContentNegotiation) {
        register(ContentType.Application.Json, JacksonConverter(Jackson.defaultMapper))
    }

    // Setup properties
    val client = "demo-client"
    val properties = OAuth2ClientProperties(this.environment.config)
    val config = properties.configFor(client)
    val cache = properties.cacheFor(client)

    // mock oAuth2 server for demo app
    val mockOAuth2Server = MockOAuth2Server()
    mockOAuth2Server.start(1111)

    // Setup OAuth Client, with configurable client assertion and post request
    val oAuth2Client = OAuth2AccessTokenClient(
        config = config,
        cache = cache,
        tokenResolver = TokenResolver(ClientAssertion(config)),
        httpClient = DefaultOAuth2HttpClient()
    )

    routing {
        get("/token") {
            val oAuth2Response = oAuth2Client.getAccessToken()
            call.respond(
                HttpStatusCode.OK,
                TokenResponse(
                    oAuth2Response.accessToken
                )
            )
        }
    }
}

object Jackson {
    val defaultMapper: ObjectMapper = jacksonObjectMapper()

    init {
        defaultMapper.configure(SerializationFeature.INDENT_OUTPUT, true)
    }
}