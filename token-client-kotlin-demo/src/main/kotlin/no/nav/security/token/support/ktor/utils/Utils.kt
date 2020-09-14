package no.nav.security.token.support.ktor.utils

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.ktor.config.ApplicationConfig
import io.ktor.util.KtorExperimentalAPI
import no.nav.security.token.support.ktor.oauth.ClientPropertiesConfig

@KtorExperimentalAPI
internal fun ApplicationConfig.propertyToString(prop: String) = this.property(prop).getString()

@KtorExperimentalAPI
internal fun ApplicationConfig.propertyToStringOrNull(prop: String) = this.propertyOrNull(prop)?.getString()

@KtorExperimentalAPI
internal fun ClientPropertiesConfig.configFor(client: String) =
    this.clientConfig[client] ?: throw RuntimeException("$client do not exist in configuration")

object Jackson {
    val defaultMapper: ObjectMapper = jacksonObjectMapper()

    init {
        defaultMapper.configure(SerializationFeature.INDENT_OUTPUT, true)
    }
}