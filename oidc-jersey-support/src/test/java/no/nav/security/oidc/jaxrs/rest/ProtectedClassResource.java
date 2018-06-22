package no.nav.security.oidc.jaxrs.rest;

import no.nav.security.oidc.api.Protected;
import org.springframework.stereotype.Component;

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
