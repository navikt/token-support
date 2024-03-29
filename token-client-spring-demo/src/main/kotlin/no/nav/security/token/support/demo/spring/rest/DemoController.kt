package no.nav.security.token.support.demo.spring.rest

import no.nav.security.token.support.core.api.Protected
import no.nav.security.token.support.core.api.Unprotected
import no.nav.security.token.support.demo.spring.client.DemoClient1
import no.nav.security.token.support.demo.spring.client.DemoClient2
import no.nav.security.token.support.demo.spring.client.DemoClient3
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@Protected
@RestController
class DemoController(private val demoClient1 : DemoClient1, private val demoClient2 : DemoClient2, private val demoClient3 : DemoClient3) {

    @GetMapping("/protected")
    fun protectedPath() = "i am protected"

    @Unprotected
    @GetMapping("/unprotected")
    fun unprotectedPath() = "i am unprotected"

    @Unprotected
    @GetMapping("/unprotected/client_credentials")
    fun pingWithClientCredentials() = demoClient1.ping()

    @GetMapping("/protected/on_behalf_of")
    fun pingWithOnBehalfOf() = demoClient2.ping()

    @GetMapping("/protected/exchange")
    fun pingExchange() = demoClient3.ping()
}