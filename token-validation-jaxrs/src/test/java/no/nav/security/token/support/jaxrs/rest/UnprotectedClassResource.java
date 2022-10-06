package no.nav.security.token.support.jaxrs.rest;

import no.nav.security.token.support.core.api.Unprotected;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;

@Path("class/unprotected")
@Unprotected
public class UnprotectedClassResource {

    @GET
    public Response get() {
        return Response.ok().build();
    }

}
