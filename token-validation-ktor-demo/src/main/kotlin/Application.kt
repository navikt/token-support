package com.example

import io.ktor.application.Application
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.auth.Authentication
import io.ktor.auth.authenticate
import io.ktor.http.ContentType
import io.ktor.response.respondText
import io.ktor.routing.get
import io.ktor.routing.routing
import io.ktor.util.KtorExperimentalAPI
import no.nav.security.token.support.core.configuration.ProxyAwareResourceRetriever
import no.nav.security.token.support.ktor.tokenValidationSupport
import no.nav.security.token.support.test.FileResourceRetriever

fun main(args: Array<String>): Unit = io.ktor.server.netty.EngineMain.main(args)

@KtorExperimentalAPI
@Suppress("unused") // Referenced in application.conf
fun Application.module(enableMock: Boolean = this.environment.config.property("no.nav.security.jwt.mock.enable").getString().toBoolean()) {

    val config = this.environment.config

    install(Authentication) {
        if (enableMock)
            tokenValidationSupport(config = config, resourceRetriever = mockResourceRetriever)
        else
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

private val mockResourceRetriever: ProxyAwareResourceRetriever =
    FileResourceRetriever("/metadata.json", "/jwkset.json")
