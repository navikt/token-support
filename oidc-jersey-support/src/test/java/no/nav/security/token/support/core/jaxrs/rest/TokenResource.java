package no.nav.security.token.support.core.jaxrs.rest;

import no.nav.security.token.support.core.jaxrs.JaxrsTokenContextHolder;
import no.nav.security.token.support.core.api.Unprotected;

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
                .entity(JaxrsTokenContextHolder.getHolder().getTokenValidationContext().getJwtToken("protected").getTokenAsString())
                .build();
    }
}
