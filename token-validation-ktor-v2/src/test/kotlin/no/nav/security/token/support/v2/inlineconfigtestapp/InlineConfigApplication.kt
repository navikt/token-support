package no.nav.security.token.support.v2.inlineconfigtestapp

import io.ktor.http.ContentType
import io.ktor.server.application.Application
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.auth.Authentication
import io.ktor.server.auth.authenticate
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import no.nav.security.token.support.v2.IssuerConfig
import no.nav.security.token.support.v2.TokenSupportConfig
import no.nav.security.token.support.v2.tokenValidationSupport

fun main(args: Array<String>): Unit = io.ktor.server.netty.EngineMain.main(args)

var helloCounter = 0

@Suppress("unused") // Referenced in application.conf
fun Application.inlineConfiguredModule() {

    install(Authentication) {
        tokenValidationSupport(config = TokenSupportConfig(
            IssuerConfig(
                name = "iss-localhost",
                acceptedAudience = listOf("aud-localhost", "anotherAudience"),
                discoveryUrl = "http://localhost:33445/.well-known/openid-configuration"
            )
        )
        )
    }

    routing {
        authenticate {
            get("/inlineconfig") {
                helloCounter++
                call.respondText("<b>Authenticated hello with inline config</b>", ContentType.Text.Html)
            }
        }
    }


}
