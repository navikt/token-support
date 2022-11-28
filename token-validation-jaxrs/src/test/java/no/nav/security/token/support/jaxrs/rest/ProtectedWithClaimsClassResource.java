package no.nav.security.token.support.jaxrs.rest;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;
import no.nav.security.token.support.core.api.ProtectedWithClaims;

@Path("class/protected/with/claims")
@ProtectedWithClaims(issuer = "protected", claimMap = {"acr=Level4"})
public class ProtectedWithClaimsClassResource {

    @GET
    public Response get() {
        return Response.ok().build();
    }

}
