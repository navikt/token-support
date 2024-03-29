package no.nav.security.token.support.jaxrs

import jakarta.ws.rs.client.ClientBuilder
import no.nav.security.token.support.core.JwtTokenConstants.AUTHORIZATION_HEADER
import no.nav.security.token.support.core.jwt.JwtToken.Companion.asBearer
import no.nav.security.token.support.jaxrs.JwtTokenGenerator.createSignedJWT
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT
import org.springframework.boot.test.web.server.LocalServerPort
import org.springframework.http.HttpStatus.OK
import org.springframework.http.HttpStatus.UNAUTHORIZED
import org.springframework.test.context.ActiveProfiles

@ActiveProfiles("protected")
@SpringBootTest(webEnvironment = RANDOM_PORT, classes = [Config::class])
internal class ServerFilterProtectedClassTest {

    @LocalServerPort
    private val port = 0

    private fun requestWithValidToken(path : String) =
        ClientBuilder.newClient().target("http://localhost:$port")
            .path(path)
            .request()
            .header(AUTHORIZATION_HEADER, createSignedJWT("12345678911").asBearer())

    private fun requestWithoutToken(path : String) =
        ClientBuilder.newClient().target("http://localhost:$port")
            .path(path)
            .request()

    @Test
    fun that_unprotected_returns_ok_with_valid_token() {
        assertEquals(OK.value(), requestWithValidToken("class/unprotected").get().status)
    }

    @Test
    fun that_protected_returns_200_with_valid_token() {
        assertEquals(OK.value(), requestWithValidToken("class/protected").get().status)
    }

    @Test
    fun that_protected_with_claims_returns_200_with_valid_token() {
        assertEquals(OK.value(), requestWithValidToken("class/protected/with/claims").get().status)
    }

    @Test
    fun that_unprotected_returns_200_without_token() {
        assertEquals(OK.value(), requestWithoutToken("class/unprotected").get().status)
    }

    @Test
    fun that_protected_returns_401_without_token() {
        assertEquals(UNAUTHORIZED.value(), requestWithoutToken("class/protected").get().status)
    }

    @Test
    fun that_protected_with_claims_returns_401_without_token() {
        assertEquals(UNAUTHORIZED.value(), requestWithoutToken("class/protected/with/claims").get().status)
    }

    @Test
    fun that_class_without_annotations_returns_401_with_filter() {
        assertEquals(UNAUTHORIZED.value(), requestWithoutToken("without/annotations").get().status)
    }
}