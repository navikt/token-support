package no.nav.security.token.support.ktor

import io.ktor.application.Application
import io.ktor.application.call
import io.ktor.http.HttpStatusCode
import io.ktor.response.respond
import io.ktor.routing.get
import io.ktor.routing.routing
import io.ktor.util.KtorExperimentalAPI
import no.nav.security.token.support.client.core.OAuth2ClientException
import no.nav.security.token.support.ktor.jwt.ClientAssertion
import no.nav.security.token.support.ktor.oauth.DefaultOAuth2HttpClient
import no.nav.security.token.support.ktor.oauth.OAuth2Client
import no.nav.security.token.support.ktor.oauth.OAuth2ClientProperties

fun main(args: Array<String>): Unit = io.ktor.server.netty.EngineMain.main(args)

@KtorExperimentalAPI
@Suppress("unused") // Referenced in application.conf
fun Application.module() {

    val clientName = "demo-client"
    val config = OAuth2ClientProperties(this.environment.config).clients[clientName]
        ?: throw OAuth2ClientException("$clientName do not exist in configuration")

    val oAuth2Client = OAuth2Client(
        clientConfig = config,
        client = ClientAssertion(config),
        httpClient = DefaultOAuth2HttpClient()
    )

    routing {
        get("/token") {
            val oAuth2Response = oAuth2Client.getAccessToken()
            call.respond(HttpStatusCode.OK, oAuth2Response.accessToken)
        }
    }
}