package no.nav.security.oidc.jaxrs.rest;

import org.springframework.stereotype.Component;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

@Component
@Path("without/annotations")
public class WithoutAnnotationsResource {

    @GET
    public Response get() {
        return Response.ok().build();
    }

}
