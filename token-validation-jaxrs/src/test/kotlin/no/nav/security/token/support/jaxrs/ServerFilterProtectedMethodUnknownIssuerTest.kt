package no.nav.security.token.support.jaxrs

import jakarta.ws.rs.client.ClientBuilder
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT
import org.springframework.boot.test.web.server.LocalServerPort
import org.springframework.http.HttpStatus.OK
import org.springframework.http.HttpStatus.UNAUTHORIZED
import org.springframework.test.annotation.DirtiesContext
import org.springframework.test.context.ActiveProfiles
import no.nav.security.token.support.core.JwtTokenConstants.AUTHORIZATION_HEADER
import no.nav.security.token.support.jaxrs.JwtTokenGenerator.createSignedJWT

@ActiveProfiles("invalid")
@DirtiesContext
@SpringBootTest(webEnvironment = RANDOM_PORT, classes = [Config::class])
internal class ServerFilterProtectedMethodUnknownIssuerTest {

    @LocalServerPort
    private val port = 0

    private fun requestWithInvalidClaimsToken(path : String) =
        ClientBuilder.newClient().target("http://localhost:$port")
            .path(path)
            .request()
            .header(AUTHORIZATION_HEADER, "Bearer " + createSignedJWT("12345678911").serialize())
            .get()

    @Test
    fun that_unprotected_returns_ok_with_invalid_token() {
        assertEquals(OK.value(), requestWithInvalidClaimsToken("unprotected").status)
    }

    @Test
    fun that_protected_returns_200_with_any_token() {
        assertEquals(OK.value(), requestWithInvalidClaimsToken("protected").status)
    }

    @Test
    fun that_protected_with_claims_returns_401_with_invalid_token() {
        assertEquals(UNAUTHORIZED.value(), requestWithInvalidClaimsToken("protected/with/claims").status)
    }
}