package com.example

import io.ktor.application.Application
import io.ktor.application.ApplicationCall
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.auth.Authentication
import io.ktor.auth.authenticate
import io.ktor.auth.authentication
import io.ktor.http.ContentType
import io.ktor.response.respondText
import io.ktor.routing.get
import io.ktor.routing.routing
import no.nav.security.token.support.ktor.RequiredClaims
import no.nav.security.token.support.ktor.TokenValidationContextPrincipal
import no.nav.security.token.support.ktor.tokenValidationSupport

fun main(args: Array<String>): Unit = io.ktor.server.netty.EngineMain.main(args)

@Suppress("unused") // Referenced in application.conf
fun Application.module() {

    val config = this.environment.config
    val acceptedIssuer = config.property("no.nav.security.jwt.issuers.0.issuer_name").getString()

    install(Authentication) {
        // Default validation
        tokenValidationSupport(config = config)

        // Only allow token with specific claim and claim value
        tokenValidationSupport(
            name = "ValidUser", config = config, requiredClaims = RequiredClaims(
                issuer = acceptedIssuer,
                claimMap = arrayOf("NAVident=X12345")
            )
        )

        // Only allow token that contains at least one matching claim and claim value
        tokenValidationSupport(
            name = "ValidUsers", config = config, requiredClaims = RequiredClaims(
                issuer = acceptedIssuer,
                claimMap = arrayOf("NAVident=X12345", "NAVident=Z12345"),
                combineWithOr = true
            )
        )

        // Only allow token that has a claim "scope" with space-separated value, where at least one scope must match
        tokenValidationSupport(name = "ValidScope", config = config, additionalValidation = { ctx ->
            val scopes = ctx.getClaims(acceptedIssuer)
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
                call.respondText("<b>Authenticated hello</b>", ContentType.Text.Html)
            }
        }

        authenticate("ValidUser") {
            get("/user") {
                val user = call.getClaim(acceptedIssuer, "NAVident")
                call.respondText("<b>Authenticated hello. NAVident: $user</b>", ContentType.Text.Html)
            }
        }

        authenticate("ValidUsers") {
            get("/users") {
                val user = call.getClaim(acceptedIssuer, "NAVident")
                call.respondText("<b>Authenticated hello. NAVident: $user</b>", ContentType.Text.Html)
            }
        }

        authenticate("ValidScope") {
            get("/scope") {
                val scope = call.getClaim(acceptedIssuer, "scope")
                call.respondText("<b>Authenticated hello. Scope: $scope</b>", ContentType.Text.Html)
            }
        }

        get("/openhello") {
            call.respondText("<b>Hello in the open</b>", ContentType.Text.Html)
        }
    }
}

private fun ApplicationCall.getClaim(issuer: String, name: String): String? =
    this.authentication.principal<TokenValidationContextPrincipal>()
        ?.context
        ?.getClaims(issuer)
        ?.getStringClaim(name)