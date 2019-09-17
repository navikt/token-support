package no.nav.security.token.support.jaxrs.rest;

import no.nav.security.token.support.core.api.ProtectedWithClaims;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

@Path("class/protected/with/claims")
@ProtectedWithClaims(issuer = "protected", claimMap = {"acr=Level4"})
public class ProtectedWithClaimsClassResource {

    @GET
    public Response get() {
        return Response.ok().build();
    }

}
