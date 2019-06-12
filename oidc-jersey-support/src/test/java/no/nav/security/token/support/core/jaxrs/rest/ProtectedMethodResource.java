package no.nav.security.token.support.core.jaxrs.rest;

import no.nav.security.token.support.core.api.Protected;
import no.nav.security.token.support.core.api.ProtectedWithClaims;
import no.nav.security.token.support.core.api.Unprotected;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

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
