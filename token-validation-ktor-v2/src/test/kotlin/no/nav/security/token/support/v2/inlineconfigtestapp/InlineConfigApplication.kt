package no.nav.security.token.support.v2.inlineconfigtestapp

import com.nimbusds.jose.util.DefaultResourceRetriever
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.netty.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import no.nav.security.token.support.core.configuration.ProxyAwareResourceRetriever.Companion.DEFAULT_HTTP_CONNECT_TIMEOUT
import no.nav.security.token.support.core.configuration.ProxyAwareResourceRetriever.Companion.DEFAULT_HTTP_READ_TIMEOUT
import no.nav.security.token.support.core.configuration.ProxyAwareResourceRetriever.Companion.DEFAULT_HTTP_SIZE_LIMIT
import no.nav.security.token.support.v2.IssuerConfig
import no.nav.security.token.support.v2.TokenSupportConfig
import no.nav.security.token.support.v2.tokenValidationSupport

fun main(args: Array<String>): Unit = EngineMain.main(args)

var helloCounter = 0

fun Application.inlineConfiguredModule() {
    install(Authentication) {
        tokenValidationSupport(config = TokenSupportConfig(IssuerConfig("iss-localhost", "http://localhost:33445/.well-known/openid-configuration", listOf("aud-localhost", "anotherAudience"))), resourceRetriever = DefaultResourceRetriever(DEFAULT_HTTP_CONNECT_TIMEOUT, DEFAULT_HTTP_READ_TIMEOUT, DEFAULT_HTTP_SIZE_LIMIT))
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