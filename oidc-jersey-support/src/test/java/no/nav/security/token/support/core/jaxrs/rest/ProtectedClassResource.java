package no.nav.security.token.support.core.jaxrs.rest;

import no.nav.security.token.support.core.api.Protected;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

@Path("class/protected")
@Protected
public class ProtectedClassResource {

    @GET
    public Response get() {
        return Response.ok().build();
    }

}
