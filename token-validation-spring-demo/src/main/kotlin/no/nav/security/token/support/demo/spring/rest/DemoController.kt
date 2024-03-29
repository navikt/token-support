package no.nav.security.token.support.demo.spring.rest

import no.nav.security.token.support.core.api.Protected
import no.nav.security.token.support.core.api.Unprotected
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@Protected
@RestController
class DemoController {

    @GetMapping("/demo/protected")
    fun protectedPath() = "I am protected"

    @Unprotected
    @GetMapping("/demo/unprotected")
    fun unprotectedPath() = "I am unprotected"
}