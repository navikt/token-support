package no.nav.security.oidc.jaxrs.rest;

import no.nav.security.oidc.jaxrs.OidcRequestContext;
import no.nav.security.oidc.api.Unprotected;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

@Path("echo")
@Unprotected
public class TokenResource {

    @GET
    @Path("token")
    public Response getToken() {
        return Response.ok()
                .entity(OidcRequestContext.getHolder().getOIDCValidationContext().getToken("protected").getIdToken())
                .build();
    }
}
