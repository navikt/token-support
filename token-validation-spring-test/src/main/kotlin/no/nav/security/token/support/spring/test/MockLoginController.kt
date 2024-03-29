package no.nav.security.token.support.spring.test

import no.nav.security.mock.oauth2.MockOAuth2Server
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/local")
class MockLoginController(private val mockOAuth2Server : MockOAuth2Server)