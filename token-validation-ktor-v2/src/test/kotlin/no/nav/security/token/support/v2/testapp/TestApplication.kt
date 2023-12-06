package no.nav.security.token.support.v2.testapp

import io.ktor.http.ContentType
import io.ktor.server.application.Application
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.auth.Authentication
import io.ktor.server.auth.authenticate
import io.ktor.server.auth.authentication
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import no.nav.security.token.support.v2.RequiredClaims
import no.nav.security.token.support.v2.TokenValidationContextPrincipal
import no.nav.security.token.support.v2.tokenValidationSupport

fun main(args: Array<String>): Unit = io.ktor.server.netty.EngineMain.main(args)

@Suppress("unused") // Referenced in application.conf
fun Application.module() {

    val config = this.environment.config
    val acceptedIssuer = "default"

    install(Authentication) {
        tokenValidationSupport("validToken", config = config)
        tokenValidationSupport("validUser", config = config,
            requiredClaims = RequiredClaims(issuer = acceptedIssuer, claimMap = arrayOf("NAVident=X112233"))
        )
        tokenValidationSupport("validGroup", config = config,
            additionalValidation = {
                val claims = it.getClaims(acceptedIssuer)
                val groups = claims.getAsList("groups")
                val hasGroup = groups != null && groups.contains("THEGROUP")
                val hasIdentRequiredForAuditLog = claims.getStringClaim("NAVident") != null
                hasGroup && hasIdentRequiredForAuditLog
            })
    }

    routing {
        authenticate("validToken") {
            get("/hello") {

                call.respondText("<b>Authenticated hello</b>", ContentType.Text.Html)
            }
        }

        authenticate("validUser") {
            get("/hello_person") {
                call.respondText("<b>Hello X112233</b>", ContentType.Text.Html)
            }
        }

        authenticate("validGroup") {
            get("/hello_group") {
                val principal: TokenValidationContextPrincipal? = call.authentication.principal()
                val ident = principal?.context?.getClaims(acceptedIssuer)?.getStringClaim("NAVident")
                println("NAVident = $ident is accessing hello_group")
                call.respondText("<b>Hello THEGROUP</b>", ContentType.Text.Html)
            }
        }

        get("/openhello") {
            call.respondText("<b>Hello in the open</b>", ContentType.Text.Html)
        }

    }


}