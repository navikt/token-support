package com.example

import io.ktor.application.*
import io.ktor.auth.Authentication
import io.ktor.auth.authenticate
import io.ktor.http.ContentType
import io.ktor.response.*
import io.ktor.routing.get
import io.ktor.routing.routing
import no.nav.security.oidc.ktor.oidcSupport

fun main(args: Array<String>): Unit = io.ktor.server.netty.EngineMain.main(args)

@Suppress("unused") // Referenced in application.conf
fun Application.module() {

    val config = this.environment.config

    install(Authentication) {
        oidcSupport(config = config)
    }

    routing {
        authenticate {
            get("/hello") {
                println("HEISANN DER JA")
                call.respondText("<b>hello</b>", ContentType.Text.Html)
            }
        }
    }


}

