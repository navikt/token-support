package no.nav.security.token.support.ktor

import io.ktor.application.Application
import io.ktor.application.call
import io.ktor.http.HttpStatusCode
import io.ktor.response.respond
import io.ktor.routing.get
import io.ktor.routing.routing
import io.ktor.util.KtorExperimentalAPI
import io.ktor.util.error
import mu.KotlinLogging
import no.nav.security.mock.oauth2.MockOAuth2Server
import no.nav.security.token.support.ktor.http.DefaultOAuth2HttpClient
import no.nav.security.token.support.ktor.jwt.ClientAssertion
import no.nav.security.token.support.ktor.oauth.OAuth2AccessTokenClient
import no.nav.security.token.support.ktor.oauth.OAuth2ClientProperties

private val log = KotlinLogging.logger { }

fun main(args: Array<String>): Unit = io.ktor.server.netty.EngineMain.main(args)

@KtorExperimentalAPI
@Suppress("unused") // Referenced in application.conf
fun Application.module() {

    val clientName = "demo-client"
    val properties = OAuth2ClientProperties(this.environment.config)
    val config = properties.getConfig(clientName)
    val cache = properties.getCache(clientName)

    val mockOAuth2Server = MockOAuth2Server()
    mockOAuth2Server.start(1111)

    val oAuth2Client = OAuth2AccessTokenClient(
        clientConfig = config,
        cache = cache,
        client = ClientAssertion(config),
        httpClient = DefaultOAuth2HttpClient()
    )

    routing {
        get("/token") {
            try {
                val oAuth2Response = oAuth2Client.getAccessToken()
                call.respond(HttpStatusCode.OK, oAuth2Response.accessToken)
            } catch (e: Exception) {
                call.respond(HttpStatusCode.InternalServerError, "Error: ${e.message}")
                log.error(e)
            }
        }
    }
}