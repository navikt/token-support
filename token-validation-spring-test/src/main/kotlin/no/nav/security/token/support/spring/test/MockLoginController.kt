package no.nav.security.token.support.spring.test

import com.nimbusds.jose.JOSEObjectType.JWT
import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletResponse
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import no.nav.security.mock.oauth2.MockOAuth2Server
import no.nav.security.mock.oauth2.token.DefaultOAuth2TokenCallback
import no.nav.security.token.support.core.api.Unprotected

@RestController
@RequestMapping("/local")
class MockLoginController(private val mockOAuth2Server : MockOAuth2Server) {
    @Unprotected
    @GetMapping("/cookie")
    fun addCookie(
        @RequestParam(value = "issuerId") issuerId : String,
        @RequestParam(value = "audience") audience : String,
        @RequestParam(value = "subject", defaultValue = "12345678910") subject : String,
        @RequestParam(value = "cookiename", defaultValue = "localhost-idtoken") cookieName : String,
        @RequestParam(value = "redirect", required = false) redirect : String?,
        @RequestParam(value = "expiry", required = false) expiry : String?, response : HttpServletResponse) =
        createCookieAndAddToResponse(response, cookieName,
            mockOAuth2Server.issueToken(issuerId, MockLoginController::class.java.simpleName,
                DefaultOAuth2TokenCallback(issuerId, subject, JWT.type, listOf(audience), mapOf("acr" to "Level4"), expiry?.toLong() ?: 3600)).serialize(), redirect)

    @Unprotected
    @PostMapping("/cookie/{issuerId}")
    fun addCookie(
        @PathVariable(value = "issuerId") issuerId : String,
        @RequestParam(value = "cookiename", defaultValue = "localhost-idtoken") cookieName : String,
        @RequestParam(value = "redirect", required = false) redirect : String?,
        @RequestBody claims : Map<String, Any>, response : HttpServletResponse) =
        createCookieAndAddToResponse(response, cookieName, mockOAuth2Server.anyToken(mockOAuth2Server.issuerUrl(issuerId), claims).serialize(), redirect)

    private fun createCookieAndAddToResponse(response : HttpServletResponse, cookieName : String, token : String, redirect : String?) : Cookie? {
        Cookie(cookieName, token).apply {
            domain = "localhost"
            path = "/"
        }.run {
            response.addCookie(this)
            redirect?.let {
                response.sendRedirect(it)
                return null
            }
            return this
        }
    }
}