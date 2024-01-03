package no.nav.security.token.support.demo.spring.client

import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Service
import org.springframework.web.client.RestClient.Builder
import org.springframework.web.client.body

@Service
class DemoClient3(@Value("\${democlient3.url}") url : String, builder : Builder) {

    private val client = builder.baseUrl(url).build()
    fun ping() = client.get()
        .uri { b -> b.path("/ping").build() }
        .retrieve()
        .body<String>()
}