package no.nav.security.token.support.ktor.testapp

import io.ktor.application.Application
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.auth.Authentication
import io.ktor.auth.authenticate
import io.ktor.auth.authentication
import io.ktor.http.ContentType
import io.ktor.response.respondText
import io.ktor.routing.get
import io.ktor.routing.routing
import no.nav.security.token.support.ktor.TokenValidationContextPrincipal
import no.nav.security.token.support.ktor.RequiredClaims
import no.nav.security.token.support.ktor.tokenValidationSupport

fun main(args: Array<String>): Unit = io.ktor.server.netty.EngineMain.main(args)

var helloCounter = 0
var helloPersonCounter = 0
var helloGroupCounter = 0
var openHelloCounter = 0

@Suppress("unused") // Referenced in application.conf
fun Application.module() {

    val config = this.environment.config
    val acceptedIssuer = "iss-localhost"

    install(Authentication) {
        tokenValidationSupport("validToken", config = config)
        tokenValidationSupport("validUser", config = config,
            requiredClaims = RequiredClaims(issuer = acceptedIssuer, claimMap = arrayOf("NAVident=X112233")))
        tokenValidationSupport("validGroup", config = config,
            additionalValidation = {
                val claims = it.getClaims(acceptedIssuer)
                val groups = claims?.getAsList("groups")
                val hasGroup = groups != null && groups.contains("THEGROUP")
                val hasIdentRequiredForAuditLog = claims?.getStringClaim("NAVident") != null
                hasGroup && hasIdentRequiredForAuditLog
            })
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

        authenticate("validGroup") {
            get("/hello_group") {
                val principal: TokenValidationContextPrincipal? = call.authentication.principal()
                val ident = principal?.context?.getClaims(acceptedIssuer)?.getStringClaim("NAVident")
                println("NAVident = $ident is accessing hello_group")
                helloGroupCounter++
                call.respondText("<b>Hello THEGROUP</b>", ContentType.Text.Html)
            }
        }

        get("/openhello") {
            openHelloCounter++
            call.respondText("<b>Hello in the open</b>", ContentType.Text.Html)
        }

    }


}
