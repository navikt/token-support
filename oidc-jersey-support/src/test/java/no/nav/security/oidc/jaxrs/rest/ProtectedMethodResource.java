package no.nav.security.oidc.jaxrs.rest;

import no.nav.security.spring.oidc.validation.api.Protected;
import no.nav.security.spring.oidc.validation.api.ProtectedWithClaims;
import no.nav.security.spring.oidc.validation.api.Unprotected;
import org.springframework.stereotype.Component;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

@Component
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
