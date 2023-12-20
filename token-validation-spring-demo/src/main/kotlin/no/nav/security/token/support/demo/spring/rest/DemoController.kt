package no.nav.security.token.support.demo.spring.rest

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import no.nav.security.token.support.core.api.Protected
import no.nav.security.token.support.core.api.Unprotected

@Protected
@RestController
class DemoController {

    @GetMapping("/demo/protected")
    fun protectedPath() : String {
        return "i am protected"
    }

    @Unprotected
    @GetMapping("/demo/unprotected")
    fun unprotectedPath() : String {
        return "i am unprotected"
    }
}