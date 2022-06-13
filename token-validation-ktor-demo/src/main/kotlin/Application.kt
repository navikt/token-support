package com.example

import io.ktor.server.application.Application
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.auth.Authentication
import io.ktor.server.auth.authenticate
import io.ktor.http.ContentType
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import no.nav.security.token.support.ktor.tokenValidationSupport

fun main(args: Array<String>): Unit = io.ktor.server.netty.EngineMain.main(args)

@Suppress("unused") // Referenced in application.conf
fun Application.module() {

    val config = this.environment.config

    install(Authentication) {
        tokenValidationSupport(config = config)
    }

    routing {
        authenticate {
            get("/hello") {
                call.respondText("<b>Authenticated hello</b>", ContentType.Text.Html)
            }
        }

        get("/openhello") {
            call.respondText("<b>Hello in the open</b>", ContentType.Text.Html)
        }

    }


}

