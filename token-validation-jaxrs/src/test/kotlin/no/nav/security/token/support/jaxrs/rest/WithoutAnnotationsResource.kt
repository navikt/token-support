package no.nav.security.token.support.jaxrs.rest

import jakarta.ws.rs.GET
import jakarta.ws.rs.Path
import jakarta.ws.rs.core.Response.ok

@Path("without/annotations")
class WithoutAnnotationsResource {

    @GET
    fun get() = ok().build()
}