package no.nav.security.oidc.jaxrs.rest;

import no.nav.security.spring.oidc.validation.api.ProtectedWithClaims;
import org.springframework.stereotype.Component;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

@Component
@Path("class/protected/with/claims")
@ProtectedWithClaims(issuer = "protected", claimMap = {"acr=Level4"})
public class ProtectedWithClaimsClassResource {

    @GET
    public Response get() {
        return Response.ok().build();
    }

}
