package no.nav.security.token.support.ktor.utils

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.ktor.config.ApplicationConfig
import io.ktor.util.KtorExperimentalAPI
import no.nav.security.token.support.ktor.oauth.OAuth2ClientProperties

@KtorExperimentalAPI
internal fun ApplicationConfig.propertyToString(prop: String) = this.property(prop).getString()

@KtorExperimentalAPI
internal fun ApplicationConfig.propertyToStringOrNull(prop: String) = this.propertyOrNull(prop)?.getString()

@KtorExperimentalAPI
internal fun OAuth2ClientProperties.configFor(client: String) =
    this.clients[client] ?: throw RuntimeException("$client do not exist in configuration")

@KtorExperimentalAPI
internal fun OAuth2ClientProperties.cacheFor(client: String) =
    this.cache[client] ?: throw RuntimeException("$client cache do not exist in configuration")

object Jackson {
    val defaultMapper: ObjectMapper = jacksonObjectMapper()

    init {
        defaultMapper.configure(SerializationFeature.INDENT_OUTPUT, true)
    }
}