package com.example

import com.nimbusds.jose.util.DefaultResourceRetriever
import io.ktor.http.ContentType.Text.Html
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
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

    val acceptedIssuer = environment.config.property("no.nav.security.jwt.issuers.0.issuer_name").getString()

    install(Authentication) {
        // Default validation
        tokenValidationSupport(config = this@module.environment.config, resourceRetriever = DefaultResourceRetriever())

        // Only allow token with specific claim and claim value
        tokenValidationSupport("ValidUser", this@module.environment.config, RequiredClaims(acceptedIssuer, arrayOf("NAVident=X12345")))

        // Only allow token that contains at least one matching claim and claim value
        tokenValidationSupport("ValidUsers", this@module.environment.config, RequiredClaims(acceptedIssuer, arrayOf("NAVident=X12345", "NAVident=Z12345"), true))

        // Only allow token that has a claim "scope" with space-separated value, where at least one scope must match
        tokenValidationSupport(name = "ValidScope",  this@module.environment.config, additionalValidation = {
            val scopes = it.getClaims(acceptedIssuer)
                .getStringClaim("scope")
                ?.split(" ")
                ?: emptyList()

            val allowedScopes = setOf("nav:domain:read", "nav:domain:write")
            scopes.any(allowedScopes::contains)
        })
    }

    routing {
        authenticate {
            get("/hello") {
                call.respondText("<b>Authenticated hello</b>", Html)
            }
        }

        authenticate("ValidUser") {
            get("/user") {
                val user = call.getClaim(acceptedIssuer, "NAVident")
                call.respondText("<b>Authenticated hello. NAVident: $user</b>", Html)
            }
        }

        authenticate("ValidUsers") {
            get("/users") {
                val user = call.getClaim(acceptedIssuer, "NAVident")
                call.respondText("<b>Authenticated hello. NAVident: $user</b>", Html)
            }
        }

        authenticate("ValidScope") {
            get("/scope") {
                val scope = call.getClaim(acceptedIssuer, "scope")
                call.respondText("<b>Authenticated hello. Scope: $scope</b>", Html)
            }
        }

        get("/openhello") {
            call.respondText("<b>Hello in the open</b>", Html)
        }
    }
}

private fun ApplicationCall.getClaim(issuer: String, name: String) =
    authentication.principal<TokenValidationContextPrincipal>()
        ?.context
        ?.getClaims(issuer)
        ?.getStringClaim(name)