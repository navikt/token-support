package no.nav.security.token.support.ktor.oauth

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.features.json.JacksonSerializer
import io.ktor.client.features.json.JsonFeature


internal val objectMapper: ObjectMapper = ObjectMapper()
    .registerKotlinModule()
    .configure(SerializationFeature.INDENT_OUTPUT, true)

internal val defaultHttpClient = HttpClient(CIO) {
    install(JsonFeature) {
        serializer = JacksonSerializer { objectMapper }
    }
}