package no.nav.security.token.support.ktor.inlineconfigtestapp

import io.ktor.application.Application
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.auth.Authentication
import io.ktor.auth.authenticate
import io.ktor.http.ContentType
import io.ktor.response.respondText
import io.ktor.routing.get
import io.ktor.routing.routing
import no.nav.security.token.support.ktor.IssuerConfig
import no.nav.security.token.support.ktor.TokenSupportConfig
import no.nav.security.token.support.ktor.tokenValidationSupport

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
