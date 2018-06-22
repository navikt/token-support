package no.nav.security.oidc.jaxrs.rest;

import no.nav.security.oidc.api.Protected;
import no.nav.security.oidc.api.ProtectedWithClaims;
import no.nav.security.oidc.api.Unprotected;
import org.springframework.stereotype.Component;

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
