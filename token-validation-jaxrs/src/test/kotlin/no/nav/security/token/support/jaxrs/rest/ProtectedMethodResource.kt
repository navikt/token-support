package no.nav.security.token.support.jaxrs.rest

import jakarta.ws.rs.GET
import jakarta.ws.rs.Path
import jakarta.ws.rs.core.Response.ok
import no.nav.security.token.support.core.api.Protected
import no.nav.security.token.support.core.api.ProtectedWithClaims
import no.nav.security.token.support.core.api.Unprotected

@Path("")
class ProtectedMethodResource {
    @GET
    @Path("unprotected")
    @Unprotected
    fun unprotected() = ok().build()
    @GET
    @Path("protected")
    @Protected
    fun protectedMethod()= ok().build()
    @GET
    @Path("protected/with/claims")
    @ProtectedWithClaims(issuer = "protected", claimMap = ["acr=Level4"])
    fun protectedWithClaims() = ok().build()

    @GET
    @Path("protected/with/claims/unknown")
    @ProtectedWithClaims(issuer = "protected", claimMap = ["acr=Level5"])
    fun protectedWithUnknownClaims() = ok().build()
}