package no.nav.security.token.support.client.core.http

import java.util.Map
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test
import no.nav.security.token.support.client.core.http.OAuth2HttpHeaders.Companion.builder
import no.nav.security.token.support.client.core.http.OAuth2HttpHeaders.Companion.of

internal class OAuth2HttpHeadersTest {

    @Test
    fun test() {
        val httpHeadersFromBuilder = builder()
            .header("header1", "header1value1")
            .header("header1", "header1value2")
            .build()
        val httpHeadersFromOf = of(Map.of("header1", listOf("header1value1",
            "header1value2")))
        Assertions.assertThat(httpHeadersFromBuilder).isEqualTo(httpHeadersFromOf)
        Assertions.assertThat(httpHeadersFromBuilder.headers).hasSize(1)
        Assertions.assertThat(httpHeadersFromBuilder.headers).isEqualTo(httpHeadersFromOf.headers)
    }
}