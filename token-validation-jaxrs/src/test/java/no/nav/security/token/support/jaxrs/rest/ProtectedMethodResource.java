package no.nav.security.token.support.jaxrs.rest;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;
import no.nav.security.token.support.core.api.Protected;
import no.nav.security.token.support.core.api.ProtectedWithClaims;
import no.nav.security.token.support.core.api.Unprotected;

@Path("")
public class ProtectedMethodResource {

    @GET
    @Path("unprotected")
    @Unprotected
    public Response unprotected() {
        return Response.ok().build();
    }

    @GET
    @Path("protected")
    @Protected
    public Response protectedMethod() {
        return Response.ok().build();
    }

    @GET
    @Path("protected/with/claims")
    @ProtectedWithClaims(issuer = "protected", claimMap = { "acr=Level4" })
    public Response protectedWithClaims() {
        return Response.ok().build();
    }

    @GET
    @Path("protected/with/claims/unknown")
    @ProtectedWithClaims(issuer = "protected", claimMap = { "acr=Level5" })
    public Response protectedWithUnknownClaims() {
        return Response.ok().build();
    }

}
