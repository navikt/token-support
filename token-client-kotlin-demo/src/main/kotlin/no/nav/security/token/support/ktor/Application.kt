package no.nav.security.token.support.ktor

import io.ktor.application.Application
import io.ktor.util.KtorExperimentalAPI
import no.nav.security.token.support.ktor.oauth.Oauth2ClientProperties

@KtorExperimentalAPI
@Suppress("unused") // Referenced in application.conf
fun Application.module() {

    val config = Oauth2ClientProperties(this.environment.config)
}