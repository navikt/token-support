package no.nav.security.token.support.jaxrs.rest;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;

@Path("without/annotations")
public class WithoutAnnotationsResource {

    @GET
    public Response get() {
        return Response.ok().build();
    }

}
