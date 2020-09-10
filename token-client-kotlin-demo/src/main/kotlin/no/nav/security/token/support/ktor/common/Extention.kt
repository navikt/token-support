package no.nav.security.token.support.ktor.common

import io.ktor.config.ApplicationConfig
import io.ktor.util.KtorExperimentalAPI

@KtorExperimentalAPI
internal fun ApplicationConfig.propertyToString(prop: String) = this.property(prop).getString()

@KtorExperimentalAPI
internal fun ApplicationConfig.propertyToStringOrNull(prop: String) = this.propertyOrNull(prop)?.getString()