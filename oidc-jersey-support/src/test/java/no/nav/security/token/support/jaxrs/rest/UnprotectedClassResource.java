package no.nav.security.token.support.jaxrs.rest;

import no.nav.security.token.support.core.api.Unprotected;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

@Path("class/unprotected")
@Unprotected
public class UnprotectedClassResource {

    @GET
    public Response get() {
        return Response.ok().build();
    }

}
