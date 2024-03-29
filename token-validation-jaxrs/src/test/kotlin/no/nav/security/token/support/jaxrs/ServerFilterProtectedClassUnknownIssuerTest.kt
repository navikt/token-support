package no.nav.security.token.support.jaxrs

import jakarta.ws.rs.client.ClientBuilder
import jakarta.ws.rs.client.Invocation.Builder
import no.nav.security.token.support.core.JwtTokenConstants.AUTHORIZATION_HEADER
import no.nav.security.token.support.core.jwt.JwtToken.Companion.asBearer
import no.nav.security.token.support.jaxrs.JwtTokenGenerator.createSignedJWT
import org.hamcrest.MatcherAssert
import org.hamcrest.Matchers
import org.hamcrest.core.Is
import org.junit.jupiter.api.Test
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT
import org.springframework.boot.test.web.server.LocalServerPort
import org.springframework.test.annotation.DirtiesContext
import org.springframework.test.context.ActiveProfiles

@ActiveProfiles("invalid")
@DirtiesContext
@SpringBootTest(webEnvironment = RANDOM_PORT, classes = [Config::class])
internal class ServerFilterProtectedClassUnknownIssuerTest {

    @LocalServerPort
    private val port = 0

    private fun requestWithInvalidClaimsToken(path : String) : Builder {
        return ClientBuilder.newClient().target("http://localhost:$port")
            .path(path)
            .request()
            .header(AUTHORIZATION_HEADER, createSignedJWT("12345678911").asBearer())
    }

    @Test
    fun that_unprotected_returns_ok_with_invalid_token() {
        val response = requestWithInvalidClaimsToken("class/unprotected").get()
        MatcherAssert.assertThat(response.status, Is.`is`(Matchers.equalTo(200)))
    }

    @Test
    fun that_protected_returns_200_with_any_token() {
        val response = requestWithInvalidClaimsToken("class/protected").get()
        MatcherAssert.assertThat(response.status, Is.`is`(Matchers.equalTo(200)))
    }

    @Test
    fun that_protected_with_claims_returns_401_with_invalid_token() {
        val response = requestWithInvalidClaimsToken("class/protected/with/claims").get()
        MatcherAssert.assertThat(response.status, Is.`is`(Matchers.equalTo(401)))
    }
}