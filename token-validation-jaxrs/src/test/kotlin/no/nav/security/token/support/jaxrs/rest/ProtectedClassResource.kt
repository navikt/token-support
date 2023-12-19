package no.nav.security.token.support.jaxrs.rest

import jakarta.ws.rs.GET
import jakarta.ws.rs.Path
import jakarta.ws.rs.core.Response
import jakarta.ws.rs.core.Response.*
import no.nav.security.token.support.core.api.Protected

@Path("class/protected")
@Protected
class ProtectedClassResource {

    @GET
    fun get() = ok().build()
}