package no.nav.security.token.support.jaxrs

import jakarta.ws.rs.client.ClientBuilder.newClient
import no.nav.security.token.support.core.JwtTokenConstants.AUTHORIZATION_HEADER
import no.nav.security.token.support.jaxrs.JwtTokenGenerator.createSignedJWT
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT
import org.springframework.boot.test.web.server.LocalServerPort
import org.springframework.http.HttpStatus.FORBIDDEN
import org.springframework.http.HttpStatus.OK
import org.springframework.http.HttpStatus.UNAUTHORIZED
import org.springframework.test.annotation.DirtiesContext
import org.springframework.test.context.ActiveProfiles

@ActiveProfiles("protected")
@DirtiesContext
@SpringBootTest(webEnvironment = RANDOM_PORT, classes = [Config::class])
internal class ServerFilterProtectedMethodTest {

    @LocalServerPort
    private val port = 0

    private fun requestWithValidToken(path : String) =
        newClient().target("http://localhost:$port")
            .path(path)
            .request()
            .header(AUTHORIZATION_HEADER, "Bearer " + createSignedJWT("12345678911").serialize())
    private fun requestWithoutToken(path : String) = newClient().target("http://localhost:$port").path(path).request()
    @Test
    fun that_unprotected_returns_ok_with_valid_token() {
        assertEquals(OK.value(), requestWithValidToken("unprotected").get().status)
    }

    @Test
    fun that_protected_returns_200_with_valid_token() {
        assertEquals(OK.value(), requestWithValidToken("protected").get().status)
    }

    @Test
    fun that_protected_with_claims_returns_200_with_valid_token() {
        assertEquals(OK.value(), requestWithValidToken("protected/with/claims").get().status)
    }

    @Test
    fun that_unprotected_returns_200_without_token() {
        assertEquals(OK.value(), requestWithoutToken("unprotected").get().status)
    }

    @Test
    fun that_protected_returns_401_without_token() {
        assertEquals(UNAUTHORIZED.value(), requestWithoutToken("protected").get().status)
    }

    @Test
    fun that_protected_with_claims_returns_401_without_token() {
        assertEquals(UNAUTHORIZED.value(), requestWithoutToken("protected/with/claims").get().status)
    }

    @Test
    fun that_protected_with_claims_returns_403_with_invalid_claims() {
        assertEquals(FORBIDDEN.value(), requestWithValidToken("protected/with/claims/unknown").get().status)
    }
}