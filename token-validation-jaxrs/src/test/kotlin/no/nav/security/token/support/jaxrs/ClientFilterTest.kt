package no.nav.security.token.support.jaxrs

import jakarta.ws.rs.client.ClientBuilder
import java.util.concurrent.ConcurrentHashMap
import no.nav.security.token.support.core.context.TokenValidationContext
import no.nav.security.token.support.core.jwt.JwtToken
import no.nav.security.token.support.jaxrs.JaxrsTokenValidationContextHolder.getHolder
import org.hamcrest.MatcherAssert
import org.hamcrest.Matchers
import org.hamcrest.core.Is
import org.junit.jupiter.api.Test
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT
import org.springframework.boot.test.web.server.LocalServerPort
import org.springframework.test.annotation.DirtiesContext
import org.springframework.test.context.ActiveProfiles

@ActiveProfiles("protected")
@DirtiesContext
@SpringBootTest(webEnvironment = RANDOM_PORT, classes = [Config::class])
internal class ClientFilterTest {

    @LocalServerPort
    private val port = 0

    private fun request() = ClientBuilder.newClient()
        .register(JwtTokenClientRequestFilter::class.java)
        .target("http://localhost:$port")
        .path("echo/token")
        .request()

    @Test
    fun that_unprotected_returns_ok_with_valid_token() {
        val token = JwtTokenGenerator.createSignedJWT("12345678911").serialize()
        addTokenToContextHolder(token)
        val returnedToken = request().get().readEntity(String::class.java)
        MatcherAssert.assertThat(returnedToken, Is.`is`(Matchers.equalTo(token)))
    }

    /**
     * Adds the token to the context holder, so it is available for the
     * [JwtTokenClientRequestFilter]. This is basically what the
     * [JwtTokenValidationFilter] filter does
     */
    private fun addTokenToContextHolder(token : String) {
        getHolder().setTokenValidationContext(createOidcValidationContext("protected", JwtToken(token)))
    }

    companion object {

        private fun createOidcValidationContext(issuerShortName : String, jwtToken : JwtToken) =
            TokenValidationContext(ConcurrentHashMap<String, JwtToken>().apply {
                put(issuerShortName, jwtToken)
            })
    }
}