package no.nav.security.token.support.jaxrs.rest

import jakarta.ws.rs.GET
import jakarta.ws.rs.Path
import jakarta.ws.rs.core.Response.ok
import no.nav.security.token.support.core.api.Unprotected
import no.nav.security.token.support.jaxrs.JaxrsTokenValidationContextHolder.getHolder

@Path("echo")
@Unprotected
class TokenResource {

    @get:Path("token")
    @get:GET
    val token = ok()
            .entity(getHolder().getTokenValidationContext().getJwtToken("protected")!!.encodedToken)
            .build()
}