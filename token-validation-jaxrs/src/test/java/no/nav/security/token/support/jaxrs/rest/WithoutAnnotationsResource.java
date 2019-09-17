package no.nav.security.token.support.jaxrs.rest;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

@Path("without/annotations")
public class WithoutAnnotationsResource {

    @GET
    public Response get() {
        return Response.ok().build();
    }

}
