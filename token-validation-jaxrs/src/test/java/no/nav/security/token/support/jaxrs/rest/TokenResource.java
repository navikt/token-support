package no.nav.security.token.support.jaxrs.rest;

import no.nav.security.token.support.core.api.Unprotected;
import no.nav.security.token.support.jaxrs.JaxrsTokenValidationContextHolder;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

@Path("echo")
@Unprotected
public class TokenResource {

    @GET
    @Path("token")
    public Response getToken() {
        return Response.ok()
                .entity(JaxrsTokenValidationContextHolder.getHolder().getTokenValidationContext().getJwtToken("protected").getTokenAsString())
                .build();
    }
}
