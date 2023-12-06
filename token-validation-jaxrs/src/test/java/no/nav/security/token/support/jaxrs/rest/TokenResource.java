package no.nav.security.token.support.jaxrs.rest;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;
import no.nav.security.token.support.core.api.Unprotected;
import no.nav.security.token.support.jaxrs.JaxrsTokenValidationContextHolder;

@Path("echo")
@Unprotected
public class TokenResource {

    @GET
    @Path("token")
    public Response getToken() {
        return Response.ok()
                .entity(JaxrsTokenValidationContextHolder.getHolder().getTokenValidationContext().getJwtToken("protected").getEncodedToken())
                .build();
    }
}