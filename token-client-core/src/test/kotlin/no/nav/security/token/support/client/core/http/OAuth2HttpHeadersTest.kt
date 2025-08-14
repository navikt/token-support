package no.nav.security.token.support.client.core.http

import no.nav.security.token.support.client.core.http.OAuth2HttpHeaders.Companion.builder
import no.nav.security.token.support.client.core.http.OAuth2HttpHeaders.Companion.of
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

internal class OAuth2HttpHeadersTest {

   // @Test
    fun test() {
        val httpHeadersFromBuilder = builder()
            .header("header1", "header1value1")
            .build()
       /*
        val httpHeadersFromOf = of(mutableMapOf("header1" to "header1value1", "header1value2")))
        assertThat(httpHeadersFromBuilder).isEqualTo(httpHeadersFromOf)
        assertThat(httpHeadersFromBuilder.headers).hasSize(1)
        assertThat(httpHeadersFromBuilder.headers).isEqualTo(httpHeadersFromOf.headers)

        */
    }
}