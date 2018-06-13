package no.nav.security.oidc.jaxrs.rest;

import no.nav.security.oidc.api.Unprotected;
import org.springframework.stereotype.Component;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

@Component
@Path("class/unprotected")
@Unprotected
public class UnprotectedClassResource {

    @GET
    public Response get() {
        return Response.ok().build();
    }

}
