package no.nav.security.token.support.ktor.testapp

import io.ktor.application.Application
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.auth.Authentication
import io.ktor.auth.authenticate
import io.ktor.http.ContentType
import io.ktor.response.respondText
import io.ktor.routing.get
import io.ktor.routing.routing
import no.nav.security.token.support.ktor.RequiredClaims
import no.nav.security.token.support.ktor.tokenValidationSupport

fun main(args: Array<String>): Unit = io.ktor.server.netty.EngineMain.main(args)

var helloCounter = 0
var helloPersonCounter = 0
var openHelloCounter = 0

@Suppress("unused") // Referenced in application.conf
fun Application.module() {

    val config = this.environment.config

    install(Authentication) {
        tokenValidationSupport("validToken", config = config)
        tokenValidationSupport("validUser", config = config,
            requiredClaims = RequiredClaims(issuer = "iss-localhost", claimMap = arrayOf("NAVident=X112233")))
    }

    routing {
        authenticate("validToken") {
            get("/hello") {
                helloCounter++
                call.respondText("<b>Authenticated hello</b>", ContentType.Text.Html)
            }
        }

        authenticate("validUser") {
            get("/hello_person") {
                helloPersonCounter++
                call.respondText("<b>Hello X112233</b>", ContentType.Text.Html)
            }
        }

        get("/openhello") {
            openHelloCounter++
            call.respondText("<b>Hello in the open</b>", ContentType.Text.Html)
        }

    }


}
